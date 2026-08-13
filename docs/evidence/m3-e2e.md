# M3 control-plane contract evidence

The M3 runtime test covers the executable hosted-control-plane evidence path:

1. An account session is created only on the configured HTTPS origin, with a
   secure, HttpOnly, same-site session cookie, a separate CSRF token, CSP, and
   `Cache-Control: no-store` on every API response.
2. A root-created pairing pointer is claimed by one account, confirmed by the
   displayed comparison code, and activated only after a matching trusted broker
   nonce/key confirmation. A browser-only flow never creates an active device.
3. A verified request envelope is visible only to its tenant. A WebAuthn adapter
   returns the bounded canonical `DecisionSubmission` bytes that the broker must
   independently verify; the service retains only an assertion reference and
   queues the opaque submission to the broker mailbox. A trusted broker receipt
   returns the terminal fake-execution projection. The service has no execution
   route and cannot create a package-install request. Duplicate request delivery
   cannot reopen a terminal projection, and concurrent ceremonies forward at
   most one decision.
4. Revocation immediately quarantines a credential. Revoking the final active
   credential puts the device in `approval_locked`; recovery/enrollment stays a
   root-pinned broker action.
5. Relay inbox delivery is authenticated, opaque, and idempotent. Delivery
   acknowledgement records receipt by an envelope/idempotency pair and never
   implies execution.

Run the control-plane contract evidence locally with:

```sh
npm run check
```

The M3 implementation remains deliberately excluded from two claims:

- It performs **no real APT/package-manager operation**. M4 owns that evidence.
- It proves one disposable tenant only. M5's PostgreSQL RLS and concurrent
  substitution suite are still required before a multi-tenant hosted alpha.
- It is not a deployable M3 exit path: `M3Runtime` is an in-memory contract
  harness. A durable hosted adapter plus real broker/relay/browser E2E and
  restart evidence are required before the milestone can be marked complete.
