=========
Umbilical
=========

---------------------------------
Durable local execution authority
---------------------------------

Umbilical is a Windows-oriented execution-authority layer for consequential
repository validation and other locally executed automation.

Its job is not to decide *what* work should exist.  Instead, it provides a
small durable boundary between an external control plane and the physical
process launch: identify the exact execution, bind the exact command, admit it
under the current controller generation, consume launch authority once, and
retain enough durable state to make retries and uncertain outcomes fail closed.

The current implementation is intentionally narrow.  Scheduling, general job
orchestration, retry policy, worker coordination, and application-specific
workflow semantics remain outside the Umbilical authority boundary.

Core model
==========

Umbilical-owned execution authority is built from a small set of durable
primitives:

* ``ControllerGeneration`` fences authority to the currently active controller
  generation.
* ``ExecutionKey`` canonically identifies one execution from repository,
  subject, revision, and causal identities.
* ``CommandSpecHash`` immutably binds an execution to the exact executable,
  argv, working directory, environment, and timeout that may be launched.
* execution admission records that the bound execution was admitted under a
  particular authority scope and controller generation.
* launch state records irreversible physical-launch consumption as
  ``intent``, ``unknown``, or ``terminal``; no later state restores launch
  authority.

Durable state is validated before use and schema changes require explicit,
versioned migration.  Missing, malformed, stale, conflicting, or ambiguous
state is rejected rather than silently recreated or repaired.

Execution boundary
==================

The local execution path snapshots an immutable command specification before
authority evaluation.  The physical process adapter then executes exact argv
with ``shell=False``, a replacement child environment, an explicit working
directory, and an explicit timeout.

Repository-facing integrations can additionally authenticate an exact remote
commit and tree, reconstruct a clean detached Git checkout, perform an
integrity preflight before consuming authority, recheck the execution contract
before registration, and publish a terminal result only after reauthenticating
the target.

This design separates disposable source checkouts from the durable authority
store and prevents a replay of the same execution identity from causing a
second physical launch.

Technology stack
================

The Umbilical-owned authority path deliberately uses a small, inspectable
stack:

* **Python 3** for authority, execution identity, validation wrappers, and CLI
  integration.
* **SQLite** through Python's ``sqlite3`` module for the durable authority
  store, transactional fencing, explicit schema validation, and migrations.
* **Windows / Win32 APIs** for the current production authority host, including
  stable per-user deployment storage obtained from Windows Known Folders.
* **Git** for exact commit/tree identity, clean detached checkouts, and
  contract-integrity checks.
* **GitHub REST API** for authenticated repository/commit observations and
  terminal commit-status publication in repository-facing integrations.
* **``subprocess``** for the narrow synchronous physical-process boundary.
* **SHA-256 and canonical byte framing** for deterministic command and
  execution identity construction.
* **Ruff**, **mypy**, and Python test tooling for static and behavioral
  verification.

Buildbot substrate
==================

Umbilical is built on a full-history import of **Buildbot v4.3.0**.  The
imported source tree preserves Buildbot's mature master, worker, process,
protocol, database, and web substrate for future use where those capabilities
are appropriate.

Umbilical's durable authority primitives are intentionally independent of
Buildbot's ``DBConnector`` and migration system, and the current physical
launch authority does not depend on Buildbot worker scheduling or its richer
``RunProcess`` path.  This keeps the consequential launch decision small and
explicit while retaining the upstream substrate around it.

The exact upstream release, tag object, commit, and history-preserving import
boundary are recorded in ``UPSTREAM.md``.

Current scope
=============

Implemented today:

* durable authority-store initialization and explicit opening;
* versioned authority-store migrations;
* controller-generation acquisition and current-generation fencing;
* canonical execution-key derivation;
* immutable command-spec binding;
* durable execution admission;
* irreversible launch claiming and terminal exit-code recording;
* replay-safe local process execution;
* exact Git target and clean-checkout validation for bounded integrations;
* authenticated terminal status publication for repository-facing adapters.

Not owned by the current authority layer:

* general-purpose scheduling;
* distributed worker coordination;
* automatic retry policy;
* arbitrary workflow semantics;
* sandboxing of repository code;
* a generic multi-repository configuration surface.

License and provenance
======================

The repository retains the upstream Buildbot history and is distributed under
the GNU General Public License, version 2.  See ``LICENSE`` for the license text
and ``UPSTREAM.md`` for import provenance.
