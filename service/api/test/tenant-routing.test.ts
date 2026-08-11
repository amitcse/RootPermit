import assert from "node:assert/strict";
import test from "node:test";

import { tenantScopeFromVerifiedSession } from "../src/tenant-context.ts";
import { accountPollingTopic, readTenantBoundCache, tenantCacheKey } from "../src/tenant-routing.ts";

const ID = "AbCdEfGhIjKlMnOpQrStUw";
const A = tenantScopeFromVerifiedSession({
  tenantId: "11111111-1111-4111-8111-111111111111",
  accountId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
});
const B = tenantScopeFromVerifiedSession({
  tenantId: "22222222-2222-4222-8222-222222222222",
  accountId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
});

test("cache keys and polling topics are tenant and account scoped", () => {
  assert.notEqual(tenantCacheKey(A, "request", ID), tenantCacheKey(B, "request", ID));
  assert.notEqual(accountPollingTopic(A, "request", ID), accountPollingTopic(B, "request", ID));
  assert.doesNotMatch(tenantCacheKey(A, "request", ID), /11111111/);
});

test("a substituted tenant-bound cache value is never returned", () => {
  assert.equal(readTenantBoundCache(A, { tenantId: B.tenantId, value: "foreign" }), undefined);
  assert.equal(readTenantBoundCache(A, { tenantId: A.tenantId, value: "own" }), "own");
});

test("routing accepts only known server resource kinds and opaque ids", () => {
  assert.throws(() => tenantCacheKey(A, "tenant", ID), /not approved/);
  assert.throws(() => accountPollingTopic(A, "request", "tenant-a"), /16-byte/);
});
