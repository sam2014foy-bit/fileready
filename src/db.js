// Database access. Every query the web app runs goes through asFirm() or
// asApp(): each opens a transaction, switches to the restricted
// fileready_app role and sets app.firm_id, so Row Level Security limits the
// whole transaction to one firm. There is deliberately no unscoped helper.

// q(sql, params) -> rows
function wrapPg(client) {
  return (sql, params) => client.query(sql, params).then((r) => r.rows);
}

export function pgDriver(pool) {
  return {
    async transaction(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(wrapPg(client));
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

export function pgliteDriver(pglite) {
  return {
    transaction(fn) {
      return pglite.transaction((tx) => fn((sql, params) => tx.query(sql, params).then((r) => r.rows)));
    },
    close: () => pglite.close(),
  };
}

export function createDb(driver) {
  async function scoped(firmId, fn) {
    return driver.transaction(async (q) => {
      await q('SET LOCAL ROLE fileready_app');
      await q(`SELECT set_config('app.firm_id', $1, true)`, [firmId ?? '']);
      return fn(q);
    });
  }
  return {
    /** Run fn(q) with access to one firm's data only. */
    asFirm(firmId, fn) {
      if (!firmId) throw new Error('asFirm needs a firm id');
      return scoped(firmId, fn);
    },
    /** Run fn(q) with no firm: only the login/session/link lookup functions work. */
    asApp(fn) {
      return scoped(null, fn);
    },
    close: () => driver.close(),
  };
}

export async function audit(q, { firmId, actorType, userId = null, action, entityType, entityId = null, details = {}, ip = null }) {
  await q(
    `INSERT INTO audit_log (firm_id, actor_type, actor_user_id, action, entity_type, entity_id, details, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [firmId, actorType, userId, action, entityType, entityId, JSON.stringify(details), ip]
  );
}
