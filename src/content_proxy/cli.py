import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from .policy import load_policy


def main():
    parser = argparse.ArgumentParser(description="Central HTTP/HTTPS content blocking proxy")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Validate a YAML policy without starting the proxy")
    check.add_argument("--config", type=Path, default=Path("config/proxy.yaml"))
    status = commands.add_parser("status", help="Read local aggregate counters")
    status.add_argument("--state-dir", type=Path, default=Path("state"))
    run = commands.add_parser("run", help="Run mitmdump with content filtering")
    run.add_argument("--config", type=Path, default=Path("config/proxy.yaml"))
    run.add_argument("--state-dir", type=Path, default=Path("state"))
    run.add_argument("--listen-host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8080)
    run.add_argument("--mode", choices=["regular", "transparent"], default="regular")
    run.add_argument(
        "--upstream-ca", type=Path, help="Additional trusted CA for private upstream servers"
    )
    args = parser.parse_args()
    try:
        if args.command == "status":
            print(json.dumps(json.loads((args.state_dir / "stats.json").read_text()), indent=2))
            return
        policy = load_policy(args.config)
        if args.command == "check":
            print(
                f"Policy OK: enabled={policy.enabled}, block={len(policy.block)}, "
                f"json={len(policy.json_rules)}, html={len(policy.html_rules)}"
            )
            return
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        executable = shutil.which("mitmdump")
        if not executable:
            raise ValueError("mitmdump is missing; install the project dependencies first")
        state = args.state_dir.resolve()
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.environ["CONTENT_PROXY_STATS"] = str(state / "stats.json")
        command = [
            executable,
            "--mode",
            args.mode,
            "--listen-host",
            args.listen_host,
            "--listen-port",
            str(args.port),
            "--set",
            f"confdir={state / 'mitmproxy'}",
            "--set",
            f"content_policy={args.config.resolve()}",
            "--set",
            "flow_detail=0",
            "--set",
            "stream_large_bodies=2m",
            "--set",
            "block_global=true",
            "--set",
            "connection_strategy=lazy",
            "-s",
            str(Path(__file__).with_name("bridge.py")),
        ]
        if args.upstream_ca:
            if not args.upstream_ca.is_file():
                raise ValueError("upstream CA file does not exist")
            command.extend(
                ["--set", f"ssl_verify_upstream_trusted_ca={args.upstream_ca.resolve()}"]
            )
        os.execv(executable, command)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
