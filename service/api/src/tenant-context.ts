/**
 * Database abstractions intentionally contain no general query entry point.
 * Repositories receive only a transaction with a server-derived TenantScope.
 */
export interface QueryResult<Row> {
  readonly rows: readonly Row[];
}

export interface TenantTransaction {
  query<Row>(sql: string, parameters?: readonly unknown[]): Promise<QueryResult<Row>>;
}

export interface TransactionDatabase {
  transaction<Result>(work: (transaction: TenantTransaction) => Promise<Result>): Promise<Result>;
}

const tenantScopeBrand: unique symbol = Symbol("TenantScope");

/** Opaque capability created only from an already verified account session. */
export interface TenantScope {
  readonly tenantId: string;
  /** The authenticated account; used only for account-owned resources. */
  readonly accountId: string;
  readonly [tenantScopeBrand]: true;
}

export interface VerifiedAccountSession {
  /** Extracted and verified by server-side session authentication, never request JSON. */
  readonly tenantId: string;
  readonly accountId: string;
}

const UUID_V4_OR_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requireUuid(value: string, field: string): string {
  if (!UUID_V4_OR_V7.test(value)) {
    throw new Error(`trusted ${field} is not a UUID`);
  }
  return value;
}

/**
 * Boundary for the session middleware. Call this only after validating the
 * signed/opaque session on the server. It deliberately accepts no HTTP body.
 */
export function tenantScopeFromVerifiedSession(session: VerifiedAccountSession): TenantScope {
  return Object.freeze({
    tenantId: requireUuid(session.tenantId, "tenant id"),
    accountId: requireUuid(session.accountId, "account id"),
    [tenantScopeBrand]: true as const,
  });
}

export class TenantScopedDatabase {
  private readonly database: TransactionDatabase;

  public constructor(database: TransactionDatabase) {
    this.database = database;
  }

  /**
   * SET LOCAL is transaction-scoped, so a pooled connection cannot retain a
   * previous tenant context. PostgreSQL RLS fails closed if this is absent.
   */
  public async withTenant<Result>(
    scope: TenantScope,
    work: (transaction: TenantTransaction) => Promise<Result>,
  ): Promise<Result> {
    return this.database.transaction(async (transaction) => {
      await transaction.query(
        "SELECT set_config('app.tenant_id', $1, true)",
        [scope.tenantId],
      );
      return work(transaction);
    });
  }
}
