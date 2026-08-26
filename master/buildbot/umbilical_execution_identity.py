# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.
#
# Umbilical is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Umbilical-owned canonical execution identity composition. Provider semantics,
# authority admission, and durable registration remain outside this module.

from __future__ import annotations

import base64

from buildbot.umbilical_authority import ExecutionKey

RepositoryIdentity = str
SubjectIdentity = str
RevisionIdentity = str
CausalRoot = str

_DOMAIN_PREFIX = b"umbilical-execution-key-v1\x00"
_MAX_COMPONENT_BYTES = (1 << 64) - 1


class InvalidExecutionIdentityError(ValueError):
    """Raised when a canonical ExecutionKey identity component is invalid."""


def _frame_identity_component(name: str, value: str) -> bytes:
    if type(value) is not str or value == "":
        raise InvalidExecutionIdentityError(
            f"{name} must be an exact non-empty string"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise InvalidExecutionIdentityError(
            f"{name} must be strictly UTF-8 encodable"
        ) from exc

    byte_length = len(encoded)
    if byte_length > _MAX_COMPONENT_BYTES:
        raise InvalidExecutionIdentityError(
            f"{name} UTF-8 byte length exceeds unsigned 64-bit framing"
        )
    return byte_length.to_bytes(8, byteorder="big", signed=False) + encoded


def derive_execution_key(
    *,
    repository_identity: RepositoryIdentity,
    subject_identity: SubjectIdentity,
    revision_identity: RevisionIdentity,
    causal_root: CausalRoot,
) -> ExecutionKey:
    """Derive the injective canonical v1 ExecutionKey for four opaque identities."""
    canonical_payload = b"".join(
        (
            _DOMAIN_PREFIX,
            _frame_identity_component("RepositoryIdentity", repository_identity),
            _frame_identity_component("SubjectIdentity", subject_identity),
            _frame_identity_component("RevisionIdentity", revision_identity),
            _frame_identity_component("CausalRoot", causal_root),
        )
    )
    encoded_payload = base64.urlsafe_b64encode(canonical_payload).decode("ascii")
    return "uek1:" + encoded_payload
