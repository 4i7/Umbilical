# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

"""Fixed, one-process WorkGraph repository-validation entrypoint."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

_REVISION = re.compile(r"[0-9a-f]{40}\Z")


def _git_argv(directory: Path, *arguments: str) -> Optional[tuple[str, ...]]:  # noqa: UP007  # Python 3.8 support
    executable = shutil.which("git")
    if executable is None or not os.path.isabs(executable):
        return None
    return (
        executable,
        "-c",
        "core.longpaths=true",
        "-C",
        str(directory),
        *arguments,
    )


def _git_output(directory: Path, *arguments: str) -> Optional[str]:  # noqa: UP007  # Python 3.8 support
    command = _git_argv(directory, *arguments)
    if command is None:
        return None
    try:
        completed = subprocess.run(
            command,
            check=False,
            shell=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _committed_clean_tree(repository_root: Path) -> Optional[str]:  # noqa: UP007  # Python 3.8 support
    top_level = _git_output(repository_root, "rev-parse", "--show-toplevel")
    head = _git_output(repository_root, "rev-parse", "HEAD")
    tree = _git_output(repository_root, "rev-parse", "HEAD^{tree}")
    status = _git_output(repository_root, "status", "--porcelain", "--untracked-files=all")
    if (
        top_level is None
        or Path(top_level).resolve() != repository_root.resolve()
        or head is None
        or _REVISION.fullmatch(head) is None
        or tree is None
        or _REVISION.fullmatch(tree) is None
        or status != ""
    ):
        return None
    return tree


def _checkout_is_exact_and_clean(
    checkout_root: Path, expected_revision: str, expected_tree: str
) -> bool:
    return (
        _git_output(checkout_root, "rev-parse", "HEAD") == expected_revision
        and _git_output(checkout_root, "rev-parse", "HEAD^{tree}") == expected_tree
        and _git_output(checkout_root, "status", "--porcelain", "--untracked-files=all") == ""
    )


def run_validation(
    checkout_root: Path,
    expected_revision: str,
    expected_tree: str,
    expected_contract_tree: str,
    *,
    integrity_only: bool = False,
) -> int:
    """Verify both exact clean trees, then optionally run the fixed validation stages."""
    contract_root = Path(__file__).resolve().parents[2]
    if _committed_clean_tree(contract_root) != expected_contract_tree:
        return 2
    if not _checkout_is_exact_and_clean(checkout_root, expected_revision, expected_tree):
        return 2
    if integrity_only:
        return 0
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
    parser.add_argument("--expected-contract-tree", required=True)
    parser.add_argument("--integrity-only", action="store_true")
    arguments = parser.parse_args(argv)
    checkout_root = Path(arguments.checkout_root).resolve()
    if not checkout_root.is_dir():
        parser.error("--checkout-root must name an existing directory")
    return run_validation(
        checkout_root,
        arguments.expected_revision,
        arguments.expected_tree,
        arguments.expected_contract_tree,
        integrity_only=arguments.integrity_only,
    )


if __name__ == "__main__":
    raise SystemExit(main())
