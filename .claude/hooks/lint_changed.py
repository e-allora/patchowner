#!/usr/bin/env python3
"""PostToolUse hook: lint and format the Python file Claude just edited.

Claude Code hands the tool call to hooks as JSON on stdin. The edited path is
tool_input.file_path. Non-Python files and files outside the repo are ignored.
"""

import json
import pathlib
import subprocess
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    path = (payload.get("tool_input") or {}).get("file_path", "")
    if not path or not path.endswith(".py"):
        return 0
    file = pathlib.Path(path)
    repo = pathlib.Path(__file__).resolve().parents[2]
    if not file.exists() or repo not in file.resolve().parents:
        return 0
    for cmd in (["uv", "run", "ruff", "check", "--fix", str(file)], ["uv", "run", "ruff", "format", str(file)]):
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if r.returncode != 0:
            # Report the lint findings back to Claude rather than failing silently.
            print((r.stdout + r.stderr).strip()[-1500:], file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
