# M2 local broker evidence

This milestone implements a local, fake-execution broker lifecycle. It never
invokes APT, a shell, `sudo`, or a package-manager helper.

## Security boundaries exercised

| Scenario | Evidence |
|---|---|
| Durable state and reboot expiry | SQLite migrations, checked descriptor opening, event-chain append, and one signed receipt in the same transaction. |
| One active request | The partial unique index includes `recovery_required`; a request remains blocking until root reconciliation proves success or failure. |
| Request binding | A root-owned Ed25519 key signs the canonical protocol `Request`, including persistent device identity, boot ID, nonce, generation, deadline, policy digest, and frozen fake plan. |
| Approval decision | The broker rebuilds its own `ApprovalContext`, uses the reviewed WebAuthn adapter with durable pinned credentials, then performs the final CAS under `BEGIN IMMEDIATE`. |
| Terminal evidence | Terminal transitions persist exactly one broker-signed COSE receipt. The requester-facing API keeps receipt retrieval in the same ownership scope as request reads. |
| Requester boundary | The local endpoint is Linux `AF_UNIX` `SOCK_SEQPACKET`; identity is obtained only through `SO_PEERCRED`. Requester and administration method spaces use distinct endpoints. |
| Root recovery | Only `recovery_required` may be reconciled; the operation records bounded root operator evidence and cannot resume execution. |

## Harness commands

Run on Linux with a runtime that permits Unix-domain sockets and user-ID test
processes:

```sh
cargo test -p rp-broker-core
cargo test -p rp-broker-api
cargo test -p rp-peercred
cargo test --workspace
```

The API suite starts an actual `SOCK_SEQPACKET` endpoint and starts a UID 65534
client through `setpriv`; it asserts the UID observed by the broker is the
kernel's `SO_PEERCRED`, not a frame field. Restricted sandboxes that deny
`socket(2)` report that capability as unavailable and skip only the process
socket assertions; Linux CI must run them without that restriction.

## Scenario coverage

The current unit and process suites cover typed input rejection, policy deny,
idempotent retries, active-slot retention, planning-to-pending request signing,
WebAuthn deny/receipt binding, terminal CAS uniqueness, reboot expiry/restart,
malformed frames, requester/admin namespace separation, and real peer-UID
derivation. Fake execution is retained intentionally: M4 owns any real APT
mutation and its independent evidence suite.
