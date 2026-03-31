const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const initDB = async () => {
  const client = await pool.connect();
  try {
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

      -- Roadmap progress table
      CREATE TABLE IF NOT EXISTS roadmap_progress (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        step_index INTEGER NOT NULL,
        item_index INTEGER NOT NULL,
        completed BOOLEAN DEFAULT TRUE,
        completed_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, step_index, item_index)
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

      -- Mentor notes table
      CREATE TABLE IF NOT EXISTS mentor_notes (
        id SERIAL PRIMARY KEY,
        mentor_id INTEGER REFERENCES users(id),
        student_id INTEGER REFERENCES users(id),
        date VARCHAR(20),
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Name columns (added later, safe to re-run)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(50) DEFAULT '';

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
