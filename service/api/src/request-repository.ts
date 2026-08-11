import {
  type TenantScope,
  type TenantTransaction,
  TenantScopedDatabase,
} from "./tenant-context.ts";

export interface RequestProjection {
  readonly publicId: string;
  readonly devicePublicId: string;
  readonly projectionState: string | null;
  readonly frozenGap: boolean | null;
  readonly terminal: boolean;
  readonly expiresAt: Date;
}

interface RequestProjectionRow {
  public_id: string;
  device_public_id: string;
  projection_state: string | null;
  frozen_gap: boolean | null;
  terminal: boolean;
  expires_at: Date;
}

const PUBLIC_ID = /^[A-Za-z0-9_-]{22}$/;

function requirePublicId(value: string): string {
  if (!PUBLIC_ID.test(value)) {
    throw new Error("public id must be a 16-byte base64url value");
  }
  return value;
}

/**
 * This repository never accepts tenant_id as a method argument and every
 * lookup includes the PostgreSQL tenant context, in addition to FORCE RLS.
 */
export class RequestRepository {
  private readonly database: TenantScopedDatabase;

  public constructor(database: TenantScopedDatabase) {
    this.database = database;
  }

  public async getByPublicId(
    scope: TenantScope,
    requestPublicId: string,
  ): Promise<RequestProjection | null> {
    const publicId = requirePublicId(requestPublicId);

    return this.database.withTenant(scope, async (transaction) => {
      const result = await transaction.query<RequestProjectionRow>(
        `SELECT request_envelopes.public_id,
                devices.public_id AS device_public_id,
                latest_projection.state AS projection_state,
                latest_projection.frozen_gap,
                request_envelopes.terminal,
                request_envelopes.expires_at
           FROM request_envelopes
           JOIN devices
             ON devices.tenant_id = request_envelopes.tenant_id
            AND devices.id = request_envelopes.device_id
      LEFT JOIN LATERAL (
             SELECT state, frozen_gap
               FROM lifecycle_projections
              WHERE lifecycle_projections.tenant_id = request_envelopes.tenant_id
                AND lifecycle_projections.request_envelope_id = request_envelopes.id
              ORDER BY lifecycle_projections.broker_sequence DESC
              LIMIT 1
           ) AS latest_projection ON true
          WHERE request_envelopes.tenant_id = rootpermit.current_tenant_id()
            AND request_envelopes.public_id = $1
          LIMIT 1`,
        [publicId],
      );
      return toProjection(result.rows[0]);
    });
  }

  public async listForDevice(
    scope: TenantScope,
    devicePublicId: string,
    limit: number,
  ): Promise<readonly RequestProjection[]> {
    const publicId = requirePublicId(devicePublicId);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("limit must be an integer from 1 through 100");
    }

    return this.database.withTenant(scope, async (transaction) => {
      const result = await transaction.query<RequestProjectionRow>(
        `SELECT request_envelopes.public_id,
                devices.public_id AS device_public_id,
                latest_projection.state AS projection_state,
                latest_projection.frozen_gap,
                request_envelopes.terminal,
                request_envelopes.expires_at
           FROM request_envelopes
           JOIN devices
             ON devices.tenant_id = request_envelopes.tenant_id
            AND devices.id = request_envelopes.device_id
      LEFT JOIN LATERAL (
             SELECT state, frozen_gap
               FROM lifecycle_projections
              WHERE lifecycle_projections.tenant_id = request_envelopes.tenant_id
                AND lifecycle_projections.request_envelope_id = request_envelopes.id
              ORDER BY lifecycle_projections.broker_sequence DESC
              LIMIT 1
           ) AS latest_projection ON true
          WHERE request_envelopes.tenant_id = rootpermit.current_tenant_id()
            AND devices.public_id = $1
          ORDER BY request_envelopes.created_at DESC
          LIMIT $2`,
        [publicId, limit],
      );
      return result.rows.map(toProjection);
    });
  }
}

function toProjection(row: RequestProjectionRow | undefined): RequestProjection | null {
  if (row === undefined) {
    return null;
  }
  return {
    publicId: row.public_id,
    devicePublicId: row.device_public_id,
    projectionState: row.projection_state,
    frozenGap: row.frozen_gap,
    terminal: row.terminal,
    expiresAt: row.expires_at,
  };
}

export async function getScopedRequest(
  transaction: TenantTransaction,
  requestPublicId: string,
): Promise<RequestProjection | null> {
  const publicId = requirePublicId(requestPublicId);
  const result = await transaction.query<RequestProjectionRow>(
    `SELECT request_envelopes.public_id,
            devices.public_id AS device_public_id,
            NULL::text AS projection_state,
            NULL::boolean AS frozen_gap,
            request_envelopes.terminal,
            request_envelopes.expires_at
       FROM request_envelopes
       JOIN devices
         ON devices.tenant_id = request_envelopes.tenant_id
        AND devices.id = request_envelopes.device_id
      WHERE request_envelopes.tenant_id = rootpermit.current_tenant_id()
        AND request_envelopes.public_id = $1
      LIMIT 1`,
    [publicId],
  );
  return toProjection(result.rows[0]);
}
