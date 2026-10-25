"""Strict, declarative policy: domain boundaries, request paths and JSON/HTML rules."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MAX_BODY_BYTES = 2 * 1024 * 1024


def host_matches(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    return domain == "*" or host == domain or host.endswith("." + domain)


@dataclass(frozen=True)
class Matcher:
    id: str
    domains: tuple[str, ...]
    path: re.Pattern[str]

    def matches(self, host: str, path: str) -> bool:
        return any(host_matches(host, d) for d in self.domains) and bool(self.path.search(path))


@dataclass(frozen=True)
class JsonRule:
    matcher: Matcher
    remove_keys: tuple[str, ...]
    remove_items_with_keys: tuple[str, ...]
    remove_items_where: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class HtmlRule:
    matcher: Matcher
    hide_selectors: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    enabled: bool = True
    max_body_bytes: int = MAX_BODY_BYTES
    allow: tuple[Matcher, ...] = field(default_factory=tuple)
    block: tuple[Matcher, ...] = field(default_factory=tuple)
    json_rules: tuple[JsonRule, ...] = field(default_factory=tuple)
    html_rules: tuple[HtmlRule, ...] = field(default_factory=tuple)

    def allowed(self, host: str, path: str) -> bool:
        return any(r.matches(host, path) for r in self.allow)


def _keys(value: dict, allowed: set[str], context: str) -> None:
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{context}: field names must be strings")
    extra = set(value) - allowed
    if extra:
        raise ValueError(f"{context}: unknown fields: {', '.join(sorted(extra))}")


def _strings(value: Any, context: str, *, empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(s, str) or not s for s in value):
        raise ValueError(f"{context}: expected a list of nonempty strings")
    if not empty and not value:
        raise ValueError(f"{context}: must not be empty")
    return tuple(value)


def _matcher(raw: dict, context: str) -> Matcher:
    if not isinstance(raw.get("id"), str) or not re.fullmatch(r"[\w.-]{1,80}", raw["id"]):
        raise ValueError(f"{context}: id must be 1-80 letters, digits, underscores, dots or dashes")
    domains = _strings(raw.get("domains"), context + ".domains", empty=False)
    normalized = []
    for domain in domains:
        domain = domain.lower().rstrip(".")
        if domain != "*" and not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", domain):
            raise ValueError(f"{context}: invalid domain {domain!r}; use plain domains, not URLs")
        normalized.append(domain)
    pattern = raw.get("path_regex", ".*")
    if not isinstance(pattern, str) or len(pattern) > 1000:
        raise ValueError(f"{context}: path_regex must be a string of at most 1000 characters")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"{context}: invalid path_regex: {exc}") from exc
    return Matcher(raw["id"], tuple(normalized), compiled)


def load_policy(path: Path) -> Policy:
    # Config is administrator-controlled. Bound its size and reject misspelled fields.
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("policy exceeds 1 MiB")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ValueError("policy must contain valid UTF-8 YAML") from exc
    if not isinstance(raw, dict):
        raise ValueError("policy must be a YAML mapping")
    _keys(
        raw,
        {
            "version",
            "enabled",
            "max_body_bytes",
            "allow_rules",
            "block_rules",
            "json_rules",
            "html_rules",
        },
        "policy",
    )
    if type(raw.get("version")) is not int or raw["version"] != 1:
        raise ValueError("policy.version must be 1")
    if type(raw.get("enabled", True)) is not bool:
        raise ValueError("policy.enabled must be boolean")
    limit = raw.get("max_body_bytes", MAX_BODY_BYTES)
    if type(limit) is not int or not 1024 <= limit <= MAX_BODY_BYTES:
        raise ValueError("max_body_bytes must be between 1024 and 2097152")
    sections: dict[str, list] = {}
    seen = set()
    base = {"id", "domains", "path_regex"}
    for section in ("allow_rules", "block_rules", "json_rules", "html_rules"):
        items = raw.get(section, [])
        if not isinstance(items, list) or len(items) > 5000:
            raise ValueError(f"{section}: expected at most 5000 rules")
        sections[section] = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{section}: each rule must be a mapping")
            extras = (
                {"remove_keys", "remove_items_with_keys", "remove_items_where"}
                if section == "json_rules"
                else {"hide_selectors"}
                if section == "html_rules"
                else set()
            )
            _keys(item, base | extras, section)
            matcher = _matcher(item, section)
            if matcher.id in seen:
                raise ValueError(f"duplicate rule id: {matcher.id}")
            seen.add(matcher.id)
            if section == "json_rules":
                keys = _strings(item.get("remove_keys", []), matcher.id + ".remove_keys")
                markers = _strings(item.get("remove_items_with_keys", []), matcher.id + ".markers")
                conditions = item.get("remove_items_where", [])
                if not isinstance(conditions, list):
                    raise ValueError(f"{matcher.id}: remove_items_where must be a list")
                for condition in conditions:
                    if not isinstance(condition, dict) or set(condition) != {"path", "equals"}:
                        raise ValueError(f"{matcher.id}: condition requires path and equals")
                    _strings(condition["path"], matcher.id + ".condition.path", empty=False)
                    if type(condition["equals"]) not in (str, bool, int, float):
                        raise ValueError(f"{matcher.id}: equals must be a non-null scalar")
                if not keys and not markers and not conditions:
                    raise ValueError(f"{matcher.id}: JSON rule has no action")
                sections[section].append(JsonRule(matcher, keys, markers, tuple(conditions)))
            elif section == "html_rules":
                selectors = _strings(item.get("hide_selectors"), matcher.id, empty=False)
                if any(any(c in s for c in "<>{}\\") for s in selectors):
                    raise ValueError(f"{matcher.id}: selectors cannot contain CSS/HTML delimiters")
                sections[section].append(HtmlRule(matcher, selectors))
            else:
                sections[section].append(matcher)
    return Policy(
        raw.get("enabled", True),
        limit,
        tuple(sections["allow_rules"]),
        tuple(sections["block_rules"]),
        tuple(sections["json_rules"]),
        tuple(sections["html_rules"]),
    )
