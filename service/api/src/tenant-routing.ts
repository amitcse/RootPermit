import { createHash } from "node:crypto";

import type { TenantScope } from "./tenant-context.ts";

const PUBLIC_ID = /^[A-Za-z0-9_-]{22}$/;
const ROUTE_KIND = /^(request|device|notification|export)$/;

/**
 * Cache keys, stream topics and notification destinations are derived from an
 * authenticated scope. No caller can provide a tenant prefix or account ID.
 */
export function tenantCacheKey(scope: TenantScope, kind: string, publicId: string): string {
  requireKind(kind);
  requirePublicId(publicId);
  return `rp:v1:${digest(scope.tenantId)}:${kind}:${publicId}`;
}

export function accountPollingTopic(scope: TenantScope, kind: string, publicId: string): string {
  requireKind(kind);
  requirePublicId(publicId);
  return `rp.v1.${digest(scope.tenantId)}.${digest(scope.accountId)}.${kind}.${publicId}`;
}

/** A cache entry always carries its bound tenant before being re-used. */
export interface TenantBoundCacheValue<Value> {
  readonly tenantId: string;
  readonly value: Value;
}

export function readTenantBoundCache<Value>(
  scope: TenantScope,
  cached: TenantBoundCacheValue<Value> | undefined,
): Value | undefined {
  return cached?.tenantId === scope.tenantId ? cached.value : undefined;
}

function digest(value: string): string {
  return createHash("sha256")
    .update("rootpermit/tenant-routing/v1\0", "utf8")
    .update(value, "utf8")
    .digest("base64url")
    .slice(0, 22);
}

function requireKind(kind: string): void {
  if (!ROUTE_KIND.test(kind)) {
    throw new Error("routing kind is not approved");
  }
}

function requirePublicId(value: string): void {
  if (!PUBLIC_ID.test(value)) {
    throw new Error("public id must be a 16-byte base64url value");
  }
}
