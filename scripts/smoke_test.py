"""End-to-end HTTP + trusted HTTPS tests against local fixtures; no external websites."""

import gzip
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml


def wait_for(predicate, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("timed out waiting for proxy")


def main():
    if not all(shutil.which(cmd) for cmd in ("curl", "openssl", "content-proxy")):
        raise SystemExit("Activate the project venv; this test also needs curl and openssl.")
    seen = Counter()

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen[self.path] += 1
            headers = {}
            if self.path.startswith("/json"):
                content = json.dumps(
                    {
                        "adPlacements": [1],
                        "streamingData": {"url": "keep"},
                        "items": [{"adSlotRenderer": {}}, {"videoRenderer": {"id": 7}}],
                    }
                ).encode()
                mime = "application/json"
                if self.path == "/json-gzip":
                    content = gzip.compress(content)
                    headers["Content-Encoding"] = "gzip"
            elif self.path == "/large":
                content = json.dumps(
                    {"adPlacements": [1], "payload": "x" * (3 * 1024 * 1024)}
                ).encode()
                mime = "application/json"
            elif self.path.startswith("/html"):
                content = b'<html><head><title>Fixture</title></head><body><div class="ad">ad</div></body></html>'
                mime = "text/html; charset=utf-8"
                if self.path == "/html-csp":
                    headers["Content-Security-Policy"] = "default-src 'none'"
            elif self.path == "/media":
                content, mime = b"unaltered-media-bytes\x00\x01", "video/mp4"
            else:
                content, mime = b"upstream-ok", "text/plain"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("ETag", '"fixture"')
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(content)

    with tempfile.TemporaryDirectory(prefix="content-proxy-smoke-") as directory:
        root = Path(directory)
        cert, key = root / "upstream.pem", root / "upstream.key"
        openssl_config = root / "openssl.cnf"
        openssl_config.write_text("""[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=localhost
[ext]
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage=serverAuth
""")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-config",
                str(openssl_config),
            ],
            check=True,
            capture_output=True,
        )
        plain = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        secure = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        secure.socket = tls.wrap_socket(secure.socket, server_side=True)
        for server in (plain, secure):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            proxy_port = probe.getsockname()[1]
        config = root / "policy.yaml"
        policy = {
            "version": 1,
            "allow_rules": [
                {"id": "allowed", "domains": ["localhost"], "path_regex": "^/allowed/"}
            ],
            "block_rules": [{"id": "blocked", "domains": ["localhost"], "path_regex": "blocked"}],
            "json_rules": [
                {
                    "id": "json",
                    "domains": ["localhost"],
                    "path_regex": "^/(json|large)",
                    "remove_keys": ["adPlacements"],
                    "remove_items_with_keys": ["adSlotRenderer"],
                }
            ],
            "html_rules": [
                {
                    "id": "html",
                    "domains": ["localhost"],
                    "path_regex": "^/html",
                    "hide_selectors": [".ad"],
                }
            ],
        }

        def save(value):
            temporary = config.with_suffix(".tmp")
            temporary.write_text(value)
            temporary.replace(config)

        save(yaml.safe_dump(policy))
        state = root / "state"
        with (root / "proxy.log").open("w+") as log:
            process = subprocess.Popen(
                [
                    "content-proxy",
                    "run",
                    "--config",
                    str(config),
                    "--state-dir",
                    str(state),
                    "--port",
                    str(proxy_port),
                    "--upstream-ca",
                    str(cert),
                ],
                stdout=log,
                stderr=log,
                env=os.environ.copy(),
            )
            try:
                ca = state / "mitmproxy/mitmproxy-ca-cert.pem"
                wait_for(lambda: ca.exists() and (state / "stats.json").exists())

                def request(path, *, https=False):
                    scheme, port = (
                        ("https", secure.server_port) if https else ("http", plain.server_port)
                    )
                    result = subprocess.run(
                        [
                            "curl",
                            "--silent",
                            "--show-error",
                            "--http1.1",
                            "--max-time",
                            "10",
                            "--noproxy",
                            "",
                            "--proxy",
                            f"http://127.0.0.1:{proxy_port}",
                            "--cacert",
                            str(ca),
                            "--write-out",
                            "\n%{http_code}",
                            f"{scheme}://localhost:{port}{path}",
                        ],
                        check=True,
                        capture_output=True,
                    )
                    body, status = result.stdout.rsplit(b"\n", 1)
                    return int(status), body

                for https in (False, True):
                    assert request("/blocked", https=https) == (204, b"")
                    assert request("/allowed/blocked", https=https) == (200, b"upstream-ok")
                    status, body = request("/json", https=https)
                    data = json.loads(body)
                    assert status == 200 and "adPlacements" not in data
                    assert data["streamingData"] == {"url": "keep"}
                    assert data["items"] == [{"videoRenderer": {"id": 7}}]
                    _, body = request("/json-gzip", https=https)
                    assert "adPlacements" not in json.loads(body)
                    _, body = request("/html", https=https)
                    assert b"content-proxy-cosmetic" in body
                    _, body = request("/html-csp", https=https)
                    assert b"content-proxy-cosmetic" not in body
                    assert request("/media", https=https) == (200, b"unaltered-media-bytes\x00\x01")
                    _, body = request("/large", https=https)
                    assert json.loads(body)["adPlacements"] == [1]
                assert seen["/blocked"] == 0
                save("version: [broken")
                wait_for(
                    lambda: json.loads((state / "stats.json").read_text())["policy_reload_error"]
                )
                assert request("/blocked") == (204, b"")
                save(yaml.safe_dump({**policy, "enabled": False}))
                wait_for(lambda: not json.loads((state / "stats.json").read_text())["enabled"])
                assert request("/blocked") == (200, b"upstream-ok")
                assert json.loads(request("/json")[1])["adPlacements"] == [1]
                print(
                    "PASS: HTTP + trusted HTTPS, URL blocking, allow precedence, JSON/gzip rewrite,"
                )
                print(
                    "      HTML/CSP, unchanged media, oversized streaming, invalid/valid live reload."
                )
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read()[-10000:])
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                for server in (plain, secure):
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    main()
