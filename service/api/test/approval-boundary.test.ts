import assert from "node:assert/strict";
import test from "node:test";

import { verifiedApprovalCeremonyFromWebAuthn } from "../src/approval-boundary.ts";

const CREDENTIAL = "AbCdEfGhIjKlMnOpQrStUw";

test("an approval ceremony is distinct from a website account session and stores only an assertion reference", () => {
  const assertion = new Uint8Array([1, 2, 3]);
  const ceremony = verifiedApprovalCeremonyFromWebAuthn({
    credentialBindingPublicId: CREDENTIAL,
    assertionBytes: assertion,
    decision: "deny",
  });
  assert.equal(ceremony.decision, "deny");
  assert.equal(ceremony.assertionReference.byteLength, 32);
  assert.notDeepEqual(ceremony.assertionReference, assertion);
  assert.equal(Object.isFrozen(ceremony), true);
});

test("the authority boundary rejects unbounded or invalid ceremony inputs", () => {
  assert.throws(() => verifiedApprovalCeremonyFromWebAuthn({
    credentialBindingPublicId: "credential-a",
    assertionBytes: new Uint8Array([1]),
    decision: "approve",
  }), /16-byte/);
  assert.throws(() => verifiedApprovalCeremonyFromWebAuthn({
    credentialBindingPublicId: CREDENTIAL,
    assertionBytes: new Uint8Array(65 * 1024),
    decision: "approve",
  }), /bounded/);
});
