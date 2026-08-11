# RootPermit development contract

RootPermit is a security boundary, not a command runner.  Development work
must preserve the claim that an unprivileged requester never receives a root
identity, shell, reusable credential, or arbitrary package-manager input.

## Prerequisites

- Linux host, Rust exactly as declared in `rust-toolchain.toml`, and Node
  exactly as declared in `.nvmrc`.
- CMake 3.24+, a C++20 compiler, and CTest.
- `libapt-pkg-dev` from the pinned Ubuntu reference image is required only for
  the M4 implementation.  M0's helper harness intentionally builds without
  linking `libapt-pkg`.

Run the fast local checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cmake -S helper/apt-helper -B build/apt-helper -DBUILD_TESTING=ON
cmake --build build/apt-helper --parallel
ctest --test-dir build/apt-helper --output-on-failure
```

`rootpermit-apt-helper` is only a startup-contract harness during M0.  It
always exits without installing a package.  Do not use it for machine setup,
and do not add a convenience CLI, package name, path, environment variable,
or network fallback to it.

## Review rules

Every pull request must have passing relevant CI lanes and a clear scoped
commit.  In addition, the following changes require a security-boundary
review by a maintainer who did not author the change:

| Change | Required evidence |
|---|---|
| `crates/rp-protocol` or `protocol-vectors` | Version decision, positive and negative vectors, byte-level expected output |
| Broker lifecycle, SQLite mutations, Unix socket code | State transition/race tests and error disclosure review |
| `helper/apt-helper`, packaging, systemd, or filesystem access | Privileged-boundary review, adversarial fixture test, and explicit recovery behavior |
| Service database/repository/worker/auth code | Two-tenant substitution test and RLS/tenant-context review |
| WebAuthn, approval UI, credentials, or revocation | Origin/RP/UV/pinned-credential and replay/generation tests |
| CI, release, dependencies, or deployment | Pin/lockfile, license, secret-scan, provenance, and rollback impact review |

Never include production credentials, real account data, broker private keys,
WebAuthn assertions, or mutable repository metadata in a test fixture or log.
When a bypass is found, add a named regression row to
`docs/threat-model.md` before treating the affected work as complete.

## Dependency and generated-file policy

- Commit lockfiles for every package manager used by a build.  CI rejects a
  manifest/lockfile mismatch.
- New runtime dependencies need a license and vulnerability review.  Avoid a
  dependency where a small, reviewed standard-library implementation suffices.
- Generated SBOMs, build output, packages, keys, and coverage reports are not
  committed.  Release automation stores them as immutable artifacts.
- Do not weaken warnings, test assertions, compiler hardening, or CI checks to
  make a change merge.  Record a bounded exception in a review document first.

## Fixture use

The JSON contract under `fixtures/` is intentionally not a runnable VM image.
M4 must replace the `contract-only` manifests with checksummed pinned images,
sealed APT inputs, and retained evidence before real helper code is enabled.
See `fixtures/CONTRACT.md`.
