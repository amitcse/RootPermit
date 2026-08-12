# VM fixture contract

`fixtures/` defines input contracts for the M4 APT-evidence gate.  It does not
provide a privileged test runner and does not authorize package installation.

## Manifest lifecycle

Each platform directory begins in `contract-only` state. Such a manifest is
valid documentation but must never be selected by a test runner.

`provisioning-ready` is deliberately narrower: CI may fetch and checksum the
declared disposable VM image, record its platform/runtime/repository identity,
and retain the provisioning log. It still must not run an APT helper test. This
separates P0's reproducible environment evidence from M4's authorization and
sealed-input evidence.

A runnable `ready` fixture may be enabled only when all of the following are
committed together:

1. Immutable image locator and SHA-256 digest, architecture and base OS
   release.
2. Immutable APT repository snapshot identity and signed Release/InRelease
   evidence, package indices, keyring fingerprint, preferences, and sealed
   archive objects with SHA-256 values.
3. Exact test case IDs, expected normalized action graph and pre-state
   observation, plus retained raw evidence path for every case.
4. Isolation requirements: disposable VM, no production network credentials,
   no host package-manager mutation, and a test-local root/state directory.
5. Expected behavior for lock contention, offline cache, hook/trigger
   observation, host drift, artifact replacement, symlink/path manipulation,
   and injected crash points.

Changing any checksummed input creates a new fixture ID.  Tests may not fetch
latest metadata, substitute an unpinned mirror, or turn an unavailable
fixture into a live-host test.

## Schema rules

`fixture-manifest.schema.json` accepts two states:

- `contract-only`: scaffolding only; `image` and test evidence are prohibited.
- `provisioning-ready`: a checksum-pinned QCOW2 image, exact architecture,
  kernel/APT/dpkg versions, immutable repository snapshot identity, and an
  artifact-retention path are required. It cannot execute APT tests.
- `ready`: additionally requires a declared sealed-input/evidence bundle. The
  M4 runner adds stricter validation before any privileged APT operation.

All fixture data is synthetic or redistributable public metadata.  It must not
contain account data, credentials, signing keys, real WebAuthn assertions, or
mutable APT state from a developer machine.
