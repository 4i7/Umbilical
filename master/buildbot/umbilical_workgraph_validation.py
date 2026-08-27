# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

"""Fixed, one-process WorkGraph repository-validation entrypoint."""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Optional
from pathlib import Path


def run_validation(checkout_root: Path) -> int:
    """Run the exact two WorkGraph validation stages without publishing status."""
    for command in (
        (sys.executable, "tools/validate.py"),
        (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
    ):
        try:
            completed = subprocess.run(
                command,
                cwd=checkout_root,
                check=False,
                shell=False,
            )
        except OSError:
            return 127
        if completed.returncode != 0:
            return completed.returncode
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout-root", required=True)
    arguments = parser.parse_args(argv)
    checkout_root = Path(arguments.checkout_root).resolve()
    if not checkout_root.is_dir():
        parser.error("--checkout-root must name an existing directory")
    return run_validation(checkout_root)

if __name__ == "__main__":
    raise SystemExit(main())
