# RootPermit implementation plan

This plan implements the approved Engineering Specification v2. It is a
single-operation privileged system: `package.install` for one native Debian
package. A passing demo never substitutes for the security evidence gates.

## Dependency plan

| Step | Modules touched | Depends on |
|---|---|---|
| M0 foundation | root config, CI, docs, fixtures, helper build | — |
| M1 protocol corpus | `crates/rp-protocol`, `protocol-vectors` | M0 toolchain contract |
| M2 broker lifecycle | broker core/API/CLI/testkit | M1 schemas and vectors |
| M3 hosted control plane | relay, service API/worker/web/migrations | M1; M2 fake lifecycle |
| M4 APT evidence | content store, C++ helper, broker executor, VM fixtures | M1, M2 |
| M5 tenant isolation | service API/worker/web/migrations | M3 foundation |
| M6 Ubuntu alpha | packaging, deployment, runbooks, end-to-end harness | M4, M5 |
| M7 ARM64 | packaging, ARM fixtures, release harness | M6, M4 |
| M8 public release | release assets, SBOM, docs, assessment evidence | M7 |

## Parallel lanes

- Lane A: M0 foundation → shared CI and fixture contracts.
- Lane B: M1 protocol and conformance corpus, isolated to `rp-protocol/` and
  `protocol-vectors/`.
- Lane C: Hosted tenant/RLS schema foundation, isolated to `service/`; it must
  consume M1 identifiers rather than define protocol bytes.
- Lane D: M2 broker lifecycle begins after M1 vector types are stable.
- Lane E: M4 helper evidence and M5 tenant propagation run in parallel only
  after M2/M3 are merged. M6 waits for both evidence reports.

The M4 and M5 lanes are intentionally not parallelized with real alpha release
work. They are blocking security claims, not implementation details.

## First implementation batch

1. Pin Rust, Node, C++ and Linux dependency versions; establish reproducible
   build, lint, test and fixture commands.
2. Define strict bounded CBOR decoding, typed identifiers, domain-separated
   SHA-256 digests, and negative byte corpus before authorization code.
3. Create the PostgreSQL tenant/RLS baseline before any hosted endpoint can
   fetch a device or request by an unscoped public identifier.
4. Add the broker SQLite lifecycle CAS, peer-credential socket authorization,
   typed package input policy, deterministic fake planner and receipt tests.
5. Only then add pairing, verified approval rendering, WebAuthn, and relay
   sequencing against the fake executor.

## Evidence gates

- M1: Rust and TypeScript consume identical positive and hostile protocol
  vectors. Unknown fields, duplicate keys, noncanonical encoding and trailing
  data must fail closed.
- M4: pinned isolated VMs prove sealed APT inputs, graph equality, lock
  handling, hostile FD/environment rejection, and crash behavior. An ambiguous
  execution is `recovery_required`.
- M5: two-tenant property/integration tests cover API, worker, polling,
  notification, export, backup and cache substitution paths.

## Current environment limitation

This workspace currently lacks Rust/Cargo, CMake, PostgreSQL, containers and
`libapt-pkg-dev`. Source and static Node checks can be authored here, but M1,
M4, M5 and release test gates need a Linux CI runner or a prepared privileged
development VM before they can be reported as passed.
