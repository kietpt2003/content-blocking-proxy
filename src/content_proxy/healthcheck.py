import json
import socket
import sys
import time
from pathlib import Path


def main():
    try:
        path = Path("/state/stats.json")
        if time.time() - path.stat().st_mtime > 30:
            raise ValueError("stale stats")
        if json.loads(path.read_text())["policy_reload_error"]:
            raise ValueError("invalid current policy")
        with socket.create_connection(("127.0.0.1", 8080), timeout=2):
            pass
    except (OSError, ValueError, KeyError):
        sys.exit(1)


if __name__ == "__main__":
    main()
