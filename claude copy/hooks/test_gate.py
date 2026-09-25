#!/usr/bin/env python3
import json
import subprocess
import sys

def main():
    try:
        input_data = json.load(sys.stdin)
    except Exception:
        input_data = {}

    # CRITICAL: Prevent infinite loop when forced continuation is already active
    if input_data.get("stop_hook_active", False):
        sys.exit(0)

    # Execute test suite via uv run pytest
    result = subprocess.run(
        ["uv", "run", "pytest"], capture_output=True, text=True, timeout=60
    )

    if result.returncode != 0:
        # Extract last 1000 characters of test output for context
        stderr_output = (
            result.stderr[-1000:]
            if result.stderr
            else result.stdout[-1000:]
        )
        output = {
            "decision": "block",
            "reason": f"Tests are failing. Fix assertions before completing:\n{stderr_output}",
        }
        print(json.dumps(output))
        sys.exit(0)

    sys.exit(0)

if __name__ == "__main__":
    main()

