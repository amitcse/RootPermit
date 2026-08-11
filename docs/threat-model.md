# RootPermit threat-model review

This document is the M0 review baseline for the one typed
`package.install` transition.  It records constraints that code review and
tests must preserve; it does not assert that real APT execution is available.

## Trust boundaries

| Asset | Untrusted or failure source | Required boundary |
|---|---|---|
| Root execution authority | Agent, requester process, relay, network | Root-only broker lifecycle; `SO_PEERCRED`; typed request; no shell or reusable grant |
| Frozen package consequence | Agent input, mutable APT state, cache/path attacker, competing package manager | Broker-sealed inputs; helper FD contract; locks, re-simulation and action equality before execution |
| Human decision | Replay, network attacker, wrong account credential, stale page | Broker nonce/context; exact digest; WebAuthn origin/RP/UV checks; pinned credential; one-time state CAS |
| Credential lifecycle | Account takeover, lost authenticator, service compromise | Root adds authority; service can only quarantine/reduce authority; credential generations |
| Tenant data | Other tenant, worker/cache/notification/support substitution | Derived tenant context, relation checks, RLS, tenant-scoped storage and jobs |
| Receipt truth | Crash, relay reorder/drop, partial package-manager mutation | Append-only local events/journal and signed receipts; no inferred rollback or success |

The hosted approval origin and its deployment pipeline are trusted MVP
components.  Their compromise can mislead a human about rendered content; this
residual risk is explicit and outside the broker's cryptographic claim.

## M0 invariants

1. No M0 component performs APT/dpkg mutation, invokes a shell, or parses a
   caller-provided package-manager command.
2. The helper has no command-line API.  The future broker invokes a fixed
   executable with no arguments and exactly `LANG=C` plus a fixed `PATH`.
3. Later helper communication is only through broker-inherited, validated
   descriptors.  Caller paths, environment, network, live APT lists/cache and
   arbitrary argv are prohibited.
4. Protocol and authority fields must be deterministic and bounded.  A new
   protocol behavior requires a versioned positive vector and a rejection
   vector.
5. A test fixture is synthetic unless it is checksummed, pinned, and contains
   no production material.  A synthetic fixture cannot support a release
   security claim.

## Required regression matrix

| ID | Adversarial case | Earliest gate | Expected result |
|---|---|---|---|
| TM-01 | Package name shell metacharacter/path/URL/flag | M2 | Typed intake rejects before planning |
| TM-02 | Cross-UID list/read/cancel | M2 | Indistinguishable `not_found_or_not_authorized` |
| TM-03 | Reused operation key with changed input | M2 | Original mapping retained; conflict returned |
| TM-04 | Noncanonical/unknown/duplicate CBOR field | M1 | Reject before signature/lifecycle use |
| TM-05 | Wrong COSE algorithm, KID, header or payload | M1 | Reject before render/acceptance |
| TM-06 | Replay or approve/deny context substitution | M2 | At most one matching decision transitions state |
| TM-07 | Wrong origin/RP ID/no UV/unpinned credential | M2 | Decision rejected; request remains pending or expires |
| TM-08 | Revoke/generation/cancel/expiry race | M2 | One durable winner; no later execution |
| TM-09 | Pairing replay or browser-only enrollment | M3 | No active device or credential |
| TM-10 | Unexpected helper FD, peer, argv or environment | M4 | Helper rejects before APT initialization |
| TM-11 | Artifact/pre-state/action graph drift | M4 | No mutation; `artifact_drift`/`prestate_drift` |
| TM-12 | Lock, hook, trigger, network, cache, symlink abuse | M4 | Fixture result matches documented claim or blocks claim |
| TM-13 | Helper/host crash during execution | M4 | Only proven final result else `recovery_required` |
| TM-14 | Cross-tenant ID/cache/job/websocket substitution | M5 | No read, decision, notification, or evidence disclosure |
| TM-15 | RLS/application guard disabled | M5 | Remaining boundary catches foreign relation where applicable |
| TM-16 | Logs/export/backup/support leak | M5 | No foreign content, assertion, token, or raw agent text |
| TM-17 | Relay duplicate/reorder/drop | M3 | Authority remains correct; projection freezes/resyncs |
| TM-18 | Dependency/CVE/toolchain regression | M8 | Locked supply-chain checks and provenance policy pass |

## Review checklist

- Is every authority-affecting input canonical, bounded, signed or kernel
  asserted, and covered by a negative test?
- Could an error disclose a foreign request/device/tenant exists?
- Does a failure fail closed without silently re-planning, retrying execution,
  or inferring package-manager rollback?
- Are logs and fixtures safe to publish?
- Does a new dependency, route, queue, cache, privilege or background worker
  add a trust boundary not represented above?  If so, update this document and
  add a regression before merging.
