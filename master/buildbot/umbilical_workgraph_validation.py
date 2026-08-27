# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

"""Fixed, one-process WorkGraph repository-validation entrypoint."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def _git_output(checkout_root: Path, *arguments: str) -> Optional[str]:  # noqa: UP007  # Python 3.8 support
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            (executable, "-C", str(checkout_root), *arguments),
            check=False,
            shell=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _checkout_is_exact_and_clean(
    checkout_root: Path, expected_revision: str, expected_tree: str
) -> bool:
    return (
        _git_output(checkout_root, "rev-parse", "HEAD") == expected_revision
        and _git_output(checkout_root, "rev-parse", "HEAD^{tree}") == expected_tree
        and _git_output(checkout_root, "status", "--porcelain", "--untracked-files=all") == ""
    )


def run_validation(checkout_root: Path, expected_revision: str, expected_tree: str) -> int:
    """Verify the exact clean tree, then run the two fixed validation stages."""
    if not _checkout_is_exact_and_clean(checkout_root, expected_revision, expected_tree):
        return 2
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


def main(argv: Optional[list[str]] = None) -> int:  # noqa: UP007  # Python 3.8 support
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout-root", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-tree", required=True)
    arguments = parser.parse_args(argv)
    checkout_root = Path(arguments.checkout_root).resolve()
    if not checkout_root.is_dir():
        parser.error("--checkout-root must name an existing directory")
    return run_validation(checkout_root, arguments.expected_revision, arguments.expected_tree)

if __name__ == "__main__":
    raise SystemExit(main())
