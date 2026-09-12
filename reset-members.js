const { Pool } = require('pg');

async function main() {
  if (process.env.RESET_MEMBER_DATA !== 'true') {
    console.log('Member data reset is disabled.');
    return;
  }
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  try {
    await pool.query('BEGIN');
    const result = await pool.query('DELETE FROM members');
    await pool.query('DELETE FROM audit_logs');
    await pool.query('COMMIT');
    console.log(`MEMBER DATA RESET COMPLETE: removed ${result.rowCount} member records. Admin accounts were preserved.`);
  } catch (err) {
    await pool.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    await pool.end();
  }
}

main().catch(err => {
  console.error('Member data reset failed:', err.message);
  process.exit(1);
});
