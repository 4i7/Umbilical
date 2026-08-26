# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

import base64
import tempfile
import unittest
from pathlib import Path

from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import ExecutionKeyRegistration
from buildbot.umbilical_execution_identity import InvalidExecutionIdentityError
from buildbot.umbilical_execution_identity import derive_execution_key


class CanonicalExecutionIdentityTests(unittest.TestCase):
    def _derive(
        self,
        repository_identity="repo",
        subject_identity="subject",
        revision_identity="revision",
        causal_root="root",
    ):
        return derive_execution_key(
            repository_identity=repository_identity,
            subject_identity=subject_identity,
            revision_identity=revision_identity,
            causal_root=causal_root,
        )

    def test_derivation_is_deterministic(self):
        first = self._derive()
        for _ in range(5):
            self.assertEqual(self._derive(), first)

    def test_golden_vector_freezes_canonical_v1_encoding(self):
        expected = (
            "uek1:dW1iaWxpY2FsLWV4ZWN1dGlvbi1rZXktdjEAAAAAAAAAAARyZXBv"
            "AAAAAAAAAAdzdWJqZWN0AAAAAAAAAAhyZXZpc2lvbgAAAAAAAAAEcm9vdA=="
        )
        actual = self._derive(
            repository_identity="repo",
            subject_identity="subject",
            revision_identity="revision",
            causal_root="root",
        )
        self.assertEqual(actual, expected)

        # Independently frozen payload: exact v1 prefix plus four uint64-be
        # UTF-8 byte lengths and exact component bytes in canonical field order.
        expected_payload = (
            b"umbilical-execution-key-v1\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x04repo"
            b"\x00\x00\x00\x00\x00\x00\x00\x07subject"
            b"\x00\x00\x00\x00\x00\x00\x00\x08revision"
            b"\x00\x00\x00\x00\x00\x00\x00\x04root"
        )
        self.assertEqual(
            base64.urlsafe_b64decode(actual.removeprefix("uek1:").encode("ascii")),
            expected_payload,
        )

    def test_each_component_difference_changes_key(self):
        baseline = {
            "repository_identity": "repo",
            "subject_identity": "subject",
            "revision_identity": "revision",
            "causal_root": "root",
        }
        baseline_key = derive_execution_key(**baseline)
        replacements = {
            "repository_identity": "repo-2",
            "subject_identity": "subject-2",
            "revision_identity": "revision-2",
            "causal_root": "root-2",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                changed = dict(baseline)
                changed[field] = replacement
                self.assertNotEqual(derive_execution_key(**changed), baseline_key)

    def test_repository_subject_order_is_significant(self):
        self.assertNotEqual(
            self._derive(repository_identity="A", subject_identity="B"),
            self._derive(repository_identity="B", subject_identity="A"),
        )

    def test_length_framing_separates_naive_concatenation_collision(self):
        self.assertNotEqual(
            self._derive(repository_identity="ab", subject_identity="c"),
            self._derive(repository_identity="a", subject_identity="bc"),
        )

    def test_case_is_preserved(self):
        self.assertNotEqual(
            self._derive(repository_identity="A"),
            self._derive(repository_identity="a"),
        )

    def test_whitespace_is_preserved(self):
        self.assertNotEqual(
            self._derive(repository_identity="repo"),
            self._derive(repository_identity=" repo "),
        )

    def test_unicode_is_not_normalized(self):
        nfc = "\u00e9"
        nfd = "e\u0301"
        self.assertNotEqual(nfc.encode("utf-8"), nfd.encode("utf-8"))
        self.assertNotEqual(
            self._derive(repository_identity=nfc),
            self._derive(repository_identity=nfd),
        )

    def test_embedded_separator_newline_nul_and_unicode_are_exact_data(self):
        component = "repo:/|\n" + chr(0) + "\u2603"
        first = self._derive(repository_identity=component)
        self.assertEqual(first, self._derive(repository_identity=component))
        self.assertNotEqual(first, self._derive(repository_identity=component + "x"))

    def test_invalid_identity_components_are_rejected(self):
        class StringSubclass(str):
            pass

        invalid_values = [
            "",
            None,
            0,
            True,
            b"repo",
            StringSubclass("repo"),
            chr(0xD800),
        ]
        fields = (
            "repository_identity",
            "subject_identity",
            "revision_identity",
            "causal_root",
        )
        baseline = {
            "repository_identity": "repo",
            "subject_identity": "subject",
            "revision_identity": "revision",
            "causal_root": "root",
        }
        for field in fields:
            for invalid in invalid_values:
                with self.subTest(field=field, invalid=repr(invalid)):
                    arguments = dict(baseline)
                    arguments[field] = invalid
                    with self.assertRaises(InvalidExecutionIdentityError):
                        derive_execution_key(**arguments)

    def test_identity_fields_are_keyword_only(self):
        with self.assertRaises(TypeError):
            derive_execution_key("repo", "subject", "revision", "root")

    def test_named_field_swap_cannot_preserve_key(self):
        normal = derive_execution_key(
            repository_identity="repository",
            subject_identity="subject",
            revision_identity="revision",
            causal_root="root",
        )
        swapped = derive_execution_key(
            repository_identity="subject",
            subject_identity="repository",
            revision_identity="revision",
            causal_root="root",
        )
        self.assertNotEqual(normal, swapped)

    def test_derived_key_integrates_with_u1b_without_schema_change(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "authority.sqlite3"
            key = self._derive(
                repository_identity="repository:/opaque",
                subject_identity="subject\nopaque",
                revision_identity="revision" + chr(0) + "opaque",
                causal_root="causal|root",
            )
            with AuthorityStore.initialize_new(path) as store:
                self.assertEqual(
                    store.register_execution_key(key), ExecutionKeyRegistration.NEW
                )
                self.assertEqual(
                    store.register_execution_key(key), ExecutionKeyRegistration.DUPLICATE
                )
                self.assertTrue(store.execution_key_exists(key))
                self.assertEqual(
                    store._connection.execute("PRAGMA user_version").fetchone(), (2,)
                )
                self.assertEqual(
                    store._connection.execute(
                        "SELECT type, name FROM sqlite_schema "
                        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                    ).fetchall(),
                    [
                        ("table", "controller_generations"),
                        ("table", "execution_keys"),
                    ],
                )
                self.assertEqual(
                    store._connection.execute(
                        "PRAGMA table_info(execution_keys)"
                    ).fetchall(),
                    [(0, "execution_key", "TEXT", 1, None, 1)],
                )


if __name__ == "__main__":
    unittest.main()
