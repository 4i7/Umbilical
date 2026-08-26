#!/usr/bin/env python3
"""Reject tracked GitHub Actions workflow paths."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", ".github/workflows/"],
        check=True,
        stdout=subprocess.PIPE,
    )

    tracked = [path for path in result.stdout.split(b"\0") if path]

    if tracked:
        print("FAIL: tracked paths exist under .github/workflows/:")
        for path in tracked:
            print(f"  {path.decode('utf-8', errors='replace')}")
        return 1

    print("PASS: no tracked path exists under .github/workflows/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
