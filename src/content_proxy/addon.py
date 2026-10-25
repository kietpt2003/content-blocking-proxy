"""mitmproxy addon. Live config reload keeps the last valid policy on errors."""

import asyncio
import json
import logging
import os
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from mitmproxy import ctx, exceptions, http

from .policy import Policy, load_policy
from .transforms import decode_body, inject_cosmetic_style, prune_json

log = logging.getLogger(__name__)


class ContentBlocker:
    def __init__(self):
        self.policy = Policy(enabled=False)
        self.policy_path: Path | None = None
        self.stamp = None
        self.task = None
        self.counters = Counter()
        self.rule_hits = Counter()
        self.started = time.time()
        self.last_reload_error = False
        self.stats_path = Path(os.environ.get("CONTENT_PROXY_STATS", "state/stats.json"))

    def load(self, loader):
        loader.add_option(
            "content_policy", str, "config/proxy.yaml", "Content blocking YAML policy"
        )

    def configure(self, updated):
        if "content_policy" in updated or self.policy_path is None:
            path = Path(ctx.options.content_policy).resolve()
            try:
                policy = load_policy(path)
                stamp = self._stamp(path)
            except (OSError, ValueError) as exc:
                raise exceptions.OptionsError(f"Cannot load content policy: {exc}") from exc
            self.policy_path, self.policy, self.stamp = path, policy, stamp
            self.last_reload_error = False

    @staticmethod
    def _stamp(path):
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size

    def reload_policy(self):
        try:
            stamp = self._stamp(self.policy_path)
            if stamp == self.stamp:
                return
            self.policy = load_policy(self.policy_path)
            self.stamp = stamp
            self.counters["policy_reloads"] += 1
            self.last_reload_error = False
            log.info("Content policy reloaded")
        except (OSError, ValueError):
            if not self.last_reload_error:
                self.counters["policy_reload_errors"] += 1
                # Do not log raw config: it may contain private URLs or credentials.
                log.error(
                    "Policy reload rejected; keeping last valid policy. Run content-proxy check."
                )
            self.last_reload_error = True

    async def running(self):
        self.write_stats()
        self.task = asyncio.create_task(self._maintenance())

    async def _maintenance(self):
        while True:
            self.reload_policy()
            self.write_stats()
            await asyncio.sleep(2)

    def write_stats(self):
        try:
            self.stats_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "updated_at": datetime.now(UTC).isoformat(),
                "uptime_seconds": int(time.time() - self.started),
                "enabled": self.policy.enabled,
                "policy_reload_error": self.last_reload_error,
                "counters": dict(self.counters),
                "rule_hits": dict(self.rule_hits),
            }
            temporary = self.stats_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.stats_path)
        except OSError:
            log.error("Cannot write local stats file")

    def done(self):
        if self.task:
            self.task.cancel()
        self.write_stats()

    def requestheaders(self, flow: http.HTTPFlow):
        policy = self.policy
        # A flow uses one immutable policy snapshot even if a reload happens mid-flight.
        flow.metadata["cb_policy"] = policy
        self.counters["requests"] += 1
        host, path = flow.request.host, flow.request.path
        if not policy.enabled or policy.allowed(host, path):
            flow.metadata["cb_skip"] = True
            return
        for rule in policy.block:
            if rule.matches(host, path):
                self.rule_hits[rule.id] += 1
                self.counters["blocked_requests"] += 1
                flow.metadata["cb_skip"] = True
                flow.response = http.Response.make(204, b"", {"Cache-Control": "no-store"})
                return
        if any(r.matcher.matches(host, path) for r in (*policy.json_rules, *policy.html_rules)):
            # Simplifies bounded rewriting. Upstreams which still return gzip are supported.
            flow.request.headers["accept-encoding"] = "identity"

    def responseheaders(self, flow: http.HTTPFlow):
        if flow.metadata.get("cb_skip") or not flow.response or flow.response.status_code != 200:
            if flow.response:
                flow.response.stream = True
            return
        policy = flow.metadata.get("cb_policy", self.policy)
        mime = flow.response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        host, path = flow.request.host, flow.request.path
        json_match = (mime == "application/json" or mime.endswith("+json")) and any(
            r.matcher.matches(host, path) for r in policy.json_rules
        )
        html_match = mime == "text/html" and any(
            r.matcher.matches(host, path) for r in policy.html_rules
        )
        try:
            length = int(flow.response.headers.get("content-length", "0"))
        except ValueError:
            length = 0
        # Media, SSE, downloads and unrelated traffic stream without body rewriting.
        # stream_large_bodies=2m also bounds unknown-length candidate buffering.
        if not (json_match or html_match) or length > policy.max_body_bytes:
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow):
        if flow.metadata.get("cb_skip") or not flow.response or flow.response.status_code != 200:
            return
        if flow.response.raw_content is None:
            return  # streamed; never reconstruct partial payloads
        policy = flow.metadata.get("cb_policy", self.policy)
        response = flow.response
        host, path = flow.request.host, flow.request.path
        mime = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        json_rules = [r for r in policy.json_rules if r.matcher.matches(host, path)]
        html_rules = [r for r in policy.html_rules if r.matcher.matches(host, path)]
        if not json_rules and not html_rules:
            return
        data = decode_body(
            response.raw_content,
            response.headers.get("content-encoding", "").lower(),
            policy.max_body_bytes,
        )
        if data is None:
            self.counters["skipped_body_encoding_or_size"] += 1
            return
        try:
            text = data.decode("utf-8")
            changed = False
            if json_rules and (mime == "application/json" or mime.endswith("+json")):
                cleaned, count = prune_json(text, json_rules)
                changed = count > 0
                if changed:
                    self.counters["removed_json_items"] += count
                    self.counters["rewritten_json_responses"] += 1
            elif html_rules and mime == "text/html":
                if "content-security-policy" in response.headers:
                    self.counters["skipped_html_csp"] += 1
                    return
                selectors = [s for rule in html_rules for s in rule.hide_selectors]
                cleaned, changed = inject_cosmetic_style(text, selectors)
                if changed:
                    self.counters["rewritten_html_responses"] += 1
            if changed:
                response.raw_content = cleaned.encode("utf-8")
                for header in (
                    "content-encoding",
                    "etag",
                    "content-md5",
                    "digest",
                    "content-digest",
                ):
                    response.headers.pop(header, None)
                response.headers["content-length"] = str(len(response.raw_content))
                response.headers["cache-control"] = "no-store"
        except (ValueError, UnicodeError, RecursionError):
            # Unknown formats (including Facebook batched/anti-XSSI JSON) pass unchanged.
            self.counters["skipped_body_format"] += 1
