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

## Implementation status (2026-08-12)

The implementation-level ticket breakdown, evidence ownership, parallel lanes,
and merge bands for the remaining M2–M5 work live in
[`docs/m2-m5-execution-backlog.md`](m2-m5-execution-backlog.md). This plan
remains the high-level dependency and release-gate source of truth.

| Milestone | Implemented in this repository | Evidence still required before the milestone can be claimed complete |
|---|---|---|
| M1 protocol | Strict CBOR schema/digest primitives and a positive/negative vector harness. | Pinned Rust toolchain execution, COSE/WebAuthn implementation, and multi-language vector consumers. |
| M2 broker | Typed package intake, idempotency, one-active-request SQLite invariant, deterministic fake planning, lifecycle CAS/race engine, hash-chained event drafts, socket peer-identity contract, and relay simulation. | Rust format/lint/unit execution; COSE-signed receipt integration; kernel socket integration tests. |
| M3 hosted control plane | Tenant/account-scoped repositories, approval ceremony boundary, decision submission model, opaque relay projection, duplicate/reorder/gap freeze/resync behavior, and tenant-scoped outbox propagation. | Root-started pairing and pinned WebAuthn verifier integration against the shared protocol corpus. |
| M4 APT helper | Fail-closed argv/environment/FD handoff, immutable content-addressed object checks, canonical manifest parsing, and action-graph normalization. | `libapt-pkg` sealed simulation/execution, locks, journal/crash recovery, and the pinned Ubuntu adversarial VM matrix. |
| M5 tenant isolation | Transaction-local tenant scope, repository guards, tenant-derived cache/polling routes, lease-safe outbox workers, migration/RLS contracts, and local substitution tests. | Live PostgreSQL RLS mutation tests and the concurrent two-tenant adversarial suite. |

The helper deliberately has no APT execution path until M4 evidence passes. The
hosted service deliberately remains a projection and coordination layer; it
cannot create broker authority or turn an account session into approval
authority.

## Current environment limitation

This workspace currently lacks Rust/Cargo, CMake, PostgreSQL, containers and
`libapt-pkg-dev`. Source and static Node checks can be authored here, but M1,
M4, M5 and release test gates need a Linux CI runner or a prepared privileged
development VM before they can be reported as passed.
