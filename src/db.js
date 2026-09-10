const { Pool } = require('pg');

const url = process.env.DATABASE_URL || '';
// Railway's internal Postgres (…railway.internal) and local DBs don't accept SSL;
// public/external URLs generally require it in production.
const isInternal = /railway\.internal|localhost|127\.0\.0\.1/.test(url);
const pool = new Pool({
  connectionString: url,
  ssl: !isInternal && process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Statements the last init could not apply. A schema problem used to be invisible
// until something downstream broke; this makes it reportable.
const initFailures = [];

// Postgres runs a multi-statement simple query inside one implicit transaction,
// so a single bad statement silently rolls back all of them — which is how a
// legacy table once blocked every migration in this file at once. Run them one
// at a time instead: a statement that cannot apply is recorded and skipped, and
// the other forty-six still land.
async function runSchema(client, sql) {
  const statements = sql
    .split('\n').map(l => l.replace(/--.*$/, '')).join('\n')  // strip line comments
    .split(';').map(x => x.trim()).filter(Boolean);
  initFailures.length = 0;
  for (const stmt of statements) {
    try {
      await client.query(stmt);
    } catch (err) {
      const label = stmt.replace(/\s+/g, ' ').slice(0, 90);
      initFailures.push({ statement: label, error: err.message, code: err.code });
      console.error('Schema statement failed [' + err.code + ']', label, '::', err.message);
    }
  }
  if (initFailures.length) {
    console.error(initFailures.length + ' of ' + statements.length + ' schema statements failed — see above');
  }
  return initFailures;
}

// Tables this app owns, each with a column it must have. This database has been
// used by something else before: a foreign "accounts" table once aborted every
// migration in this file, and a foreign "payouts" relation later made
// CREATE TABLE IF NOT EXISTS a silent no-op, so its indexes had no columns to
// index and every query against it failed at runtime. A name that is taken by a
// relation of the wrong shape gets moved aside once — renamed, never dropped, so
// whatever is in there survives — and this app then creates its own.
const OWNED_TABLES = [
  ['users', 'username'], ['trades', 'user_id'], ['daily_journals', 'user_id'],
  ['badges', 'user_id'], ['milestones', 'user_id'], ['risk_plans', 'user_id'],
  ['user_settings', 'user_id'], ['coach_messages', 'user_id'], ['coach_memory', 'user_id'],
  ['accounts', 'user_id'], ['payouts', 'user_id'], ['mentor_notes', 'mentor_id'],
  ['app_state', 'key'], ['ots_cohorts', 'start_date'], ['ots_members', 'user_id'],
  ['ots_reflections', 'user_id']
];

async function reserveTableNames(client) {
  for (const [name, mustHave] of OWNED_TABLES) {
    const rel = await client.query(
      "SELECT table_type FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1", [name]);
    if (!rel.rows.length) continue;                       // free, we will create it
    const col = await client.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
      [name, mustHave]);
    if (col.rows.length) continue;                        // already ours
    const isView = rel.rows[0].table_type === 'VIEW';
    let target = name + '_legacy_backup', n = 1;
    while ((await client.query(
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1", [target])).rows.length) {
      target = name + '_legacy_backup_' + (++n);
    }
    // Identifiers come from the fixed list above plus a generated suffix.
    await client.query('ALTER ' + (isView ? 'VIEW' : 'TABLE') + ' "' + name + '" RENAME TO "' + target + '"');
    console.log('Reserved "' + name + '": a foreign ' + (isView ? 'view' : 'table') +
      ' held that name without a ' + mustHave + ' column, renamed to "' + target + '"');
  }
}

const initDB = async () => {
  const client = await pool.connect();
  try {
    await reserveTableNames(client);
    await runSchema(client, `
      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_mentor BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Trades table
      CREATE TABLE IF NOT EXISTS trades (
        id VARCHAR(20) PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        date VARCHAR(20) NOT NULL,
        instrument VARCHAR(20) DEFAULT 'futures',
        ticker VARCHAR(50) NOT NULL,
        direction VARCHAR(10) NOT NULL,
        entry_price VARCHAR(30) DEFAULT '',
        exit_price VARCHAR(30) DEFAULT '',
        quantity VARCHAR(20) DEFAULT '1',
        stop_loss VARCHAR(30) DEFAULT '',
        pnl DECIMAL(12,2) DEFAULT 0,
        fees DECIMAL(12,2) DEFAULT 0,
        gross_pnl DECIMAL(12,2) DEFAULT 0,
        strategy VARCHAR(255) DEFAULT 'No Strategy Used',
        emotion_rating INTEGER DEFAULT 7,
        rules_followed TEXT[] DEFAULT '{}',
        notes TEXT DEFAULT '',
        screenshots TEXT[] DEFAULT '{}',
        imported_from VARCHAR(20) DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Daily journals table
      CREATE TABLE IF NOT EXISTS daily_journals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        date VARCHAR(20) NOT NULL,
        satisfaction INTEGER DEFAULT 0,
        emotions TEXT[] DEFAULT '{}',
        biases TEXT[] DEFAULT '{}',
        lessons TEXT DEFAULT '',
        observations TEXT DEFAULT '',
        gameplan TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, date)
      );

      -- Badges table
      CREATE TABLE IF NOT EXISTS badges (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        badge_id VARCHAR(50) NOT NULL,
        earned_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, badge_id)
      );

      -- Milestones table
      CREATE TABLE IF NOT EXISTS milestones (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        milestone_id VARCHAR(50) NOT NULL,
        earned_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, milestone_id)
      );

      -- Risk plan table
      CREATE TABLE IF NOT EXISTS risk_plans (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        account_size DECIMAL(12,2) DEFAULT 0,
        account_type VARCHAR(20) DEFAULT 'Funded',
        max_loss_per_trade DECIMAL(12,2) DEFAULT 0,
        max_loss_per_day DECIMAL(12,2) DEFAULT 0,
        max_loss_per_week DECIMAL(12,2) DEFAULT 0,
        max_drawdown DECIMAL(12,2) DEFAULT 0,
        max_trades_per_day INTEGER DEFAULT 3,
        personal_rules TEXT DEFAULT ''
      );

      -- User settings table
      CREATE TABLE IF NOT EXISTS user_settings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        custom_fees JSONB DEFAULT '{}',
        walkthrough_done BOOLEAN DEFAULT FALSE,
        journal_completions JSONB DEFAULT '{}'
      );

      -- Coach chat messages
      CREATE TABLE IF NOT EXISTS coach_messages (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        role VARCHAR(10) NOT NULL,
        content TEXT NOT NULL,
        has_image BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Coach structured memory
      CREATE TABLE IF NOT EXISTS coach_memory (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        kind VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Prop firm accounts
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(80) NOT NULL,
        firm VARCHAR(80) DEFAULT '',
        env VARCHAR(10) DEFAULT 'demo',
        broker_ids TEXT DEFAULT '',
        tv_user VARCHAR(120) DEFAULT '',
        tv_pass_enc TEXT DEFAULT '',
        phase VARCHAR(20) DEFAULT 'eval',
        profit_target DECIMAL(12,2) DEFAULT 0,
        max_drawdown DECIMAL(12,2) DEFAULT 0,
        min_days INTEGER DEFAULT 0,
        consistency_pct INTEGER DEFAULT 0,
        payout_min DECIMAL(12,2) DEFAULT 0,
        last_sync TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- App state (cron guards etc.)
      CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value TEXT
      );

      -- Mentor notes table
      CREATE TABLE IF NOT EXISTS mentor_notes (
        id SERIAL PRIMARY KEY,
        mentor_id INTEGER REFERENCES users(id),
        student_id INTEGER REFERENCES users(id),
        date VARCHAR(20),
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Security question columns (added later, safe to re-run)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question VARCHAR(255) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer VARCHAR(255) DEFAULT '';

      -- Name columns (added later, safe to re-run)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(50) DEFAULT '';

      -- Account link on trades (added later, safe to re-run)
      ALTER TABLE trades ADD COLUMN IF NOT EXISTS account_id INTEGER;

      -- Prop firm account state (added later, safe to re-run).
      -- account_size is the nominal size (50000) and fixes a STATIC drawdown floor.
      -- anchor_balance/anchor_date are the "balance as of" marker the balance is
      -- computed forward from; a CSV only ever covers part of an account's life.
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS account_size DECIMAL(12,2) DEFAULT 0;
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS anchor_balance DECIMAL(12,2) DEFAULT 0;
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS anchor_date VARCHAR(20) DEFAULT '';
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS dd_type VARCHAR(20) DEFAULT 'static';
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS dd_amount DECIMAL(12,2) DEFAULT 0;
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS dd_lock DECIMAL(12,2) DEFAULT 0;
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hwm_override DECIMAL(12,2) DEFAULT 0;
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
      -- The balance the firm requires you to leave in the account. Whatever sits
      -- above it is what you can actually take out.
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS retain_balance DECIMAL(12,2) DEFAULT 0;

      -- Money taken off an account. A payout lowers the balance but never the
      -- drawdown floor, which is exactly what makes withdrawals risky.
      -- ═══ OTS: a fixed-length cohort sprint ═══
      -- One shared start date so "day 12" means the same day for everyone in
      -- the cohort, which is what makes the mentor's grid comparable.
      CREATE TABLE IF NOT EXISTS ots_cohorts (
        id SERIAL PRIMARY KEY,
        name VARCHAR(80) NOT NULL UNIQUE,
        start_date VARCHAR(20) NOT NULL,
        total_days INTEGER DEFAULT 90,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS ots_members (
        id SERIAL PRIMARY KEY,
        cohort_id INTEGER,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        joined_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(cohort_id, user_id)
      );

      -- One reflection per person per calendar day. kept_prior records whether
      -- they followed through on what the previous day said they would bring in,
      -- which is the thread that makes ninety entries a chain rather than a pile.
      CREATE TABLE IF NOT EXISTS ots_reflections (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        cohort_id INTEGER,
        date VARCHAR(20) NOT NULL,
        day_num INTEGER,
        learned TEXT DEFAULT '',
        bringing TEXT DEFAULT '',
        kept_prior BOOLEAN,
        written_on VARCHAR(20) DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, date)
      );

      CREATE TABLE IF NOT EXISTS payouts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        account_id INTEGER,
        date VARCHAR(20) NOT NULL,
        amount DECIMAL(12,2) NOT NULL DEFAULT 0,
        note TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Manual day entries: a day recorded without executions (blown account, missing export)
      ALTER TABLE trades ADD COLUMN IF NOT EXISTS manual_day BOOLEAN DEFAULT FALSE;
      ALTER TABLE trades ADD COLUMN IF NOT EXISTS trade_count INTEGER;

      -- Normalize legacy M/D/YY and MM/DD/YYYY trade dates to ISO (idempotent)
      UPDATE trades SET date = to_char(
        to_date(date, CASE WHEN date ~ '/[0-9]{4}$' THEN 'FMMM/FMDD/YYYY' ELSE 'FMMM/FMDD/YY' END),
        'YYYY-MM-DD')
      WHERE date ~ '^[0-9]{1,2}/[0-9]{1,2}/[0-9]{2,4}$';

      -- Pre-market columns (added later, safe to re-run)
      ALTER TABLE daily_journals ADD COLUMN IF NOT EXISTS pm_bias VARCHAR(20) DEFAULT '';
      ALTER TABLE daily_journals ADD COLUMN IF NOT EXISTS pm_mental_state INTEGER DEFAULT 0;
      ALTER TABLE daily_journals ADD COLUMN IF NOT EXISTS pm_levels TEXT DEFAULT '';
      ALTER TABLE daily_journals ADD COLUMN IF NOT EXISTS pm_goals TEXT DEFAULT '';
      ALTER TABLE daily_journals ADD COLUMN IF NOT EXISTS pm_rules TEXT[] DEFAULT '{}';

      -- One-time cleanup: a midnight-fired roll call wrongly stamped 2026-08-17
      -- as posted; clear it so the real 5:30pm post fires. No-op after that date.
      DELETE FROM app_state WHERE key = 'rollcall_last' AND value = '2026-08-17';

      -- Create indexes
      CREATE INDEX IF NOT EXISTS idx_trades_user_id ON trades(user_id);
      CREATE INDEX IF NOT EXISTS idx_trades_date ON trades(date);
      CREATE INDEX IF NOT EXISTS idx_trades_user_date ON trades(user_id, date);
      CREATE INDEX IF NOT EXISTS idx_daily_journals_user ON daily_journals(user_id);
      CREATE INDEX IF NOT EXISTS idx_badges_user ON badges(user_id);
      CREATE INDEX IF NOT EXISTS idx_milestones_user ON milestones(user_id);
      CREATE INDEX IF NOT EXISTS idx_coach_messages_user ON coach_messages(user_id);
      CREATE INDEX IF NOT EXISTS idx_coach_memory_user ON coach_memory(user_id);
      CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
      CREATE INDEX IF NOT EXISTS idx_trades_account ON trades(account_id);
      CREATE INDEX IF NOT EXISTS idx_payouts_user ON payouts(user_id);
      CREATE INDEX IF NOT EXISTS idx_payouts_account ON payouts(account_id);
      CREATE INDEX IF NOT EXISTS idx_ots_members_user ON ots_members(user_id);
      CREATE INDEX IF NOT EXISTS idx_ots_refl_user ON ots_reflections(user_id);
      CREATE INDEX IF NOT EXISTS idx_ots_refl_date ON ots_reflections(date);

      -- Seed the first cohort. Safe to re-run: the name is unique and the start
      -- date is only written once, so editing it later in the app sticks.
      INSERT INTO ots_cohorts (name, start_date, total_days)
        VALUES ('OTS 1', '2026-09-14', 90) ON CONFLICT (name) DO NOTHING;
    `);
    // Founding OTS 1 members, enrolled exactly once. The app_state guard means
    // removing someone later in the Mentor Panel sticks instead of being undone
    // on the next deploy, and anyone who is not a user yet is simply added by
    // hand rather than silently re-seeded forever.
    try {
      // Versioned guard: the first pass ran before ktdtech's username was known,
      // so it needs to run once more against the corrected roster. Bumping the
      // key is how a member is added at deploy time without re-adding anyone the
      // mentor has since removed.
      const done = await client.query("SELECT 1 FROM app_state WHERE key = 'ots1_seeded_v2'");
      if (!done.rows.length) {
        const seeded = await client.query(
          `INSERT INTO ots_members (cohort_id, user_id)
           SELECT c.id, u.id FROM users u CROSS JOIN ots_cohorts c
            WHERE c.name = 'OTS 1' AND LOWER(u.username) = ANY($1)
           ON CONFLICT (cohort_id, user_id) DO NOTHING
           RETURNING user_id`,
          [['seansolano', 'ktdtech']]);
        // Only stamp the guard once someone was actually enrolled. A fresh
        // database boots before any user exists, and stamping there would lock
        // the seed out forever; once it has run, a member removed in the app
        // stays removed.
        if (seeded.rowCount) {
          await client.query("INSERT INTO app_state (key, value) VALUES ('ots1_seeded_v2', $1) ON CONFLICT (key) DO NOTHING", [String(seeded.rowCount)]);
          console.log('OTS 1: enrolled ' + seeded.rowCount + ' member(s)');
        }
      }
    } catch (e) { console.error('OTS seed skipped:', e.message); }
    try {
      const moved = await client.query(
        `UPDATE ots_cohorts SET start_date = to_char(now() AT TIME ZONE 'America/New_York', 'YYYY-MM-DD')
          WHERE name = 'OTS 1' AND start_date = '2026-09-14'
            AND NOT EXISTS (SELECT 1 FROM ots_reflections r WHERE r.cohort_id = ots_cohorts.id)
            AND NOT EXISTS (SELECT 1 FROM app_state WHERE key = 'ots1_started')
          RETURNING start_date`);
      if (moved.rowCount) {
        await client.query("INSERT INTO app_state (key, value) VALUES ('ots1_started', $1) ON CONFLICT (key) DO NOTHING", [moved.rows[0].start_date]);
        console.log('OTS 1: start date brought forward to ' + moved.rows[0].start_date + ' so the page is live; set it back from the roster when the real cohort begins');
      }
    } catch (e) { console.error('OTS start-date move skipped:', e.message); }
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  } finally {
    client.release();
  }
};

module.exports = { pool, initDB, initFailures };
