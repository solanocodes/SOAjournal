const { Pool } = require('pg');

const url = process.env.DATABASE_URL || '';
// Railway's internal Postgres (…railway.internal) and local DBs don't accept SSL;
// public/external URLs generally require it in production.
const isInternal = /railway\.internal|localhost|127\.0\.0\.1/.test(url);
const pool = new Pool({
  connectionString: url,
  ssl: !isInternal && process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const initDB = async () => {
  const client = await pool.connect();
  try {
    // A legacy "accounts" table (pre-dating this app's schema, no user_id column)
    // blocks index creation and aborts the whole init. Move it aside, keep the data.
    const hasAccounts = await client.query(
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'accounts'");
    if (hasAccounts.rows.length) {
      const hasUserId = await client.query(
        "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'accounts' AND column_name = 'user_id'");
      if (!hasUserId.rows.length) {
        await client.query('ALTER TABLE accounts RENAME TO accounts_legacy_backup');
        console.log('Renamed legacy accounts table to accounts_legacy_backup');
      }
    }
    await client.query(`
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
    `);
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  } finally {
    client.release();
  }
};

module.exports = { pool, initDB };
