require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const { pool, initDB } = require('./db');
const { generateToken, authMiddleware, mentorOnly } = require('./auth');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '..', 'site')));

// ═══════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, firstName, lastName, securityQuestion, securityAnswer } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!firstName || !lastName) return res.status(400).json({ error: 'First and last name required' });
    if (!securityQuestion || !securityAnswer) return res.status(400).json({ error: 'Security question and answer required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });

    const existing = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (existing.rows.length) return res.status(400).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    const isMentor = username.toLowerCase() === 'seansolano';
    const answerHash = await bcrypt.hash(securityAnswer.trim().toLowerCase(), 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, is_mentor, first_name, last_name, security_question, security_answer) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, username, is_mentor, first_name, last_name',
      [username, hash, isMentor, firstName.trim(), lastName.trim(), securityQuestion.trim(), answerHash]
    );
    const user = result.rows[0];
    const token = generateToken(user);
    res.json({ token, user: { id: user.id, username: user.username, is_mentor: user.is_mentor, firstName: user.first_name, lastName: user.last_name } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ token, user: { id: user.id, username: user.username, is_mentor: user.is_mentor } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/security-question', async (req, res) => {
  try {
    const { username } = req.body;
    const result = await pool.query('SELECT security_question FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!result.rows.length) return res.status(404).json({ error: 'Account not found' });
    const q = result.rows[0].security_question;
    if (!q) return res.status(400).json({ error: 'No security question set for this account' });
    res.json({ question: q });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { username, securityAnswer, newPassword } = req.body;
    if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    const result = await pool.query('SELECT id, security_answer FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!result.rows.length) return res.status(404).json({ error: 'Account not found' });
    const user = result.rows[0];
    if (!user.security_answer) return res.status(400).json({ error: 'No security question set for this account' });
    const valid = await bcrypt.compare(securityAnswer.trim().toLowerCase(), user.security_answer);
    if (!valid) return res.status(401).json({ error: 'Incorrect answer' });
    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({ user: req.user });
});

// ═══════════════════════════════════
// TRADES ROUTES
// ═══════════════════════════════════

app.get('/api/trades', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM trades WHERE user_id = $1 ORDER BY date DESC, created_at DESC',
      [req.user.id]
    );
    const trades = result.rows.map(r => ({
      id: r.id, date: r.date, instrument: r.instrument, ticker: r.ticker,
      direction: r.direction, entryPrice: r.entry_price, exitPrice: r.exit_price,
      quantity: r.quantity, stopLoss: r.stop_loss, pnl: parseFloat(r.pnl),
      fees: parseFloat(r.fees), grossPnl: parseFloat(r.gross_pnl),
      strategy: r.strategy, emotionRating: r.emotion_rating,
      rulesFollowed: r.rules_followed || [], notes: r.notes,
      screenshots: r.screenshots || [], importedFrom: r.imported_from
    }));
    res.json(trades);
  } catch (err) {
    console.error('Get trades error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/trades', authMiddleware, async (req, res) => {
  try {
    const t = req.body;
    await pool.query(
      `INSERT INTO trades (id, user_id, date, instrument, ticker, direction, entry_price, exit_price, quantity, stop_loss, pnl, fees, gross_pnl, strategy, emotion_rating, rules_followed, notes, screenshots, imported_from)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       ON CONFLICT (id) DO UPDATE SET
         date=EXCLUDED.date, instrument=EXCLUDED.instrument, ticker=EXCLUDED.ticker,
         direction=EXCLUDED.direction, entry_price=EXCLUDED.entry_price, exit_price=EXCLUDED.exit_price,
         quantity=EXCLUDED.quantity, stop_loss=EXCLUDED.stop_loss, pnl=EXCLUDED.pnl,
         fees=EXCLUDED.fees, gross_pnl=EXCLUDED.gross_pnl, strategy=EXCLUDED.strategy,
         emotion_rating=EXCLUDED.emotion_rating, rules_followed=EXCLUDED.rules_followed,
         notes=EXCLUDED.notes, screenshots=EXCLUDED.screenshots, imported_from=EXCLUDED.imported_from`,
      [t.id, req.user.id, t.date, t.instrument||'futures', t.ticker, t.direction,
       t.entryPrice||'', t.exitPrice||'', t.quantity||'1', t.stopLoss||'',
       t.pnl||0, t.fees||0, t.grossPnl||t.pnl||0, t.strategy||'No Strategy Used',
       t.emotionRating||7, t.rulesFollowed||[], t.notes||'',
       t.screenshots||[], t.importedFrom||'']
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Save trade error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/trades/bulk', authMiddleware, async (req, res) => {
  try {
    const trades = req.body.trades || [];
    const upsert = req.body.upsert || false;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const t of trades) {
        const conflictClause = upsert
          ? `ON CONFLICT (id) DO UPDATE SET
              date=EXCLUDED.date, instrument=EXCLUDED.instrument, ticker=EXCLUDED.ticker,
              direction=EXCLUDED.direction, entry_price=EXCLUDED.entry_price, exit_price=EXCLUDED.exit_price,
              quantity=EXCLUDED.quantity, stop_loss=EXCLUDED.stop_loss, pnl=EXCLUDED.pnl,
              fees=EXCLUDED.fees, gross_pnl=EXCLUDED.gross_pnl, strategy=EXCLUDED.strategy,
              emotion_rating=EXCLUDED.emotion_rating, rules_followed=EXCLUDED.rules_followed,
              notes=EXCLUDED.notes, screenshots=EXCLUDED.screenshots, imported_from=EXCLUDED.imported_from`
          : `ON CONFLICT (id) DO NOTHING`;
        await client.query(
          `INSERT INTO trades (id, user_id, date, instrument, ticker, direction, entry_price, exit_price, quantity, stop_loss, pnl, fees, gross_pnl, strategy, emotion_rating, rules_followed, notes, screenshots, imported_from)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
           ${conflictClause}`,
          [t.id, req.user.id, t.date, t.instrument||'futures', t.ticker, t.direction,
           t.entryPrice||'', t.exitPrice||'', t.quantity||'1', t.stopLoss||'',
           t.pnl||0, t.fees||0, t.grossPnl||t.pnl||0, t.strategy||'No Strategy Used',
           t.emotionRating||7, t.rulesFollowed||[], t.notes||'',
           t.screenshots||[], t.importedFrom||'']
        );
      }
      await client.query('COMMIT');
      res.json({ success: true, count: trades.length });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Bulk import error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/trades/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM trades WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════
// DAILY JOURNALS ROUTES
// ═══════════════════════════════════

app.get('/api/journals', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM daily_journals WHERE user_id = $1', [req.user.id]);
    const journals = {};
    result.rows.forEach(r => {
      journals[r.date] = {
        satisfaction: r.satisfaction, emotions: r.emotions || [],
        biases: r.biases || [], lessons: r.lessons || '',
        observations: r.observations || '', gameplan: r.gameplan || '',
        pmBias: r.pm_bias || '', pmMentalState: r.pm_mental_state || 0,
        pmLevels: r.pm_levels || '', pmGoals: r.pm_goals || '',
        pmRules: r.pm_rules || []
      };
    });
    res.json(journals);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/journals/:date', authMiddleware, async (req, res) => {
  try {
    const { date } = req.params;
    const j = req.body;
    await pool.query(
      `INSERT INTO daily_journals (user_id, date, satisfaction, emotions, biases, lessons, observations, gameplan, pm_bias, pm_mental_state, pm_levels, pm_goals, pm_rules)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (user_id, date) DO UPDATE SET
         satisfaction=EXCLUDED.satisfaction, emotions=EXCLUDED.emotions, biases=EXCLUDED.biases,
         lessons=EXCLUDED.lessons, observations=EXCLUDED.observations, gameplan=EXCLUDED.gameplan,
         pm_bias=EXCLUDED.pm_bias, pm_mental_state=EXCLUDED.pm_mental_state,
         pm_levels=EXCLUDED.pm_levels, pm_goals=EXCLUDED.pm_goals, pm_rules=EXCLUDED.pm_rules`,
      [req.user.id, date, j.satisfaction||0, j.emotions||[], j.biases||[],
       j.lessons||'', j.observations||'', j.gameplan||'',
       j.pmBias||'', j.pmMentalState||0, j.pmLevels||'', j.pmGoals||'', j.pmRules||[]]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════
// BADGES & MILESTONES ROUTES
// ═══════════════════════════════════

app.get('/api/badges', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT badge_id, earned_at FROM badges WHERE user_id = $1', [req.user.id]);
    const badges = {};
    result.rows.forEach(r => { badges[r.badge_id] = r.earned_at; });
    res.json(badges);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/badges/:badgeId', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO badges (user_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, req.params.badgeId]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/milestones', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT milestone_id, earned_at FROM milestones WHERE user_id = $1', [req.user.id]);
    const milestones = {};
    result.rows.forEach(r => { milestones[r.milestone_id] = r.earned_at; });
    res.json(milestones);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/milestones/:milestoneId', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO milestones (user_id, milestone_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, req.params.milestoneId]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// ROADMAP ROUTES
// ═══════════════════════════════════

app.get('/api/roadmap', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT step_index, item_index FROM roadmap_progress WHERE user_id = $1',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/roadmap', authMiddleware, async (req, res) => {
  try {
    const { stepIndex, itemIndex, completed } = req.body;
    if (completed) {
      await pool.query(
        'INSERT INTO roadmap_progress (user_id, step_index, item_index) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
        [req.user.id, stepIndex, itemIndex]
      );
    } else {
      await pool.query(
        'DELETE FROM roadmap_progress WHERE user_id=$1 AND step_index=$2 AND item_index=$3',
        [req.user.id, stepIndex, itemIndex]
      );
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/roadmap/sync', authMiddleware, async (req, res) => {
  try {
    const items = req.body.items || [];
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM roadmap_progress WHERE user_id = $1', [req.user.id]);
      for (const item of items) {
        await client.query(
          'INSERT INTO roadmap_progress (user_id, step_index, item_index) VALUES ($1,$2,$3)',
          [req.user.id, item.stepIndex, item.itemIndex]
        );
      }
      await client.query('COMMIT');
      res.json({ success: true });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// RISK PLAN ROUTES
// ═══════════════════════════════════

app.get('/api/riskplan', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM risk_plans WHERE user_id = $1', [req.user.id]);
    if (!result.rows.length) return res.json({});
    const r = result.rows[0];
    res.json({
      accountSize: parseFloat(r.account_size), accountType: r.account_type,
      maxLossPerTrade: parseFloat(r.max_loss_per_trade), maxLossPerDay: parseFloat(r.max_loss_per_day),
      maxLossPerWeek: parseFloat(r.max_loss_per_week), maxDrawdown: parseFloat(r.max_drawdown),
      maxTradesPerDay: r.max_trades_per_day, personalRules: r.personal_rules
    });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/riskplan', authMiddleware, async (req, res) => {
  try {
    const rp = req.body;
    await pool.query(
      `INSERT INTO risk_plans (user_id, account_size, account_type, max_loss_per_trade, max_loss_per_day, max_loss_per_week, max_drawdown, max_trades_per_day, personal_rules)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (user_id) DO UPDATE SET
         account_size=EXCLUDED.account_size, account_type=EXCLUDED.account_type,
         max_loss_per_trade=EXCLUDED.max_loss_per_trade, max_loss_per_day=EXCLUDED.max_loss_per_day,
         max_loss_per_week=EXCLUDED.max_loss_per_week, max_drawdown=EXCLUDED.max_drawdown,
         max_trades_per_day=EXCLUDED.max_trades_per_day, personal_rules=EXCLUDED.personal_rules`,
      [req.user.id, rp.accountSize||0, rp.accountType||'Funded', rp.maxLossPerTrade||0,
       rp.maxLossPerDay||0, rp.maxLossPerWeek||0, rp.maxDrawdown||0,
       rp.maxTradesPerDay||3, rp.personalRules||'']
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// SETTINGS ROUTES
// ═══════════════════════════════════

app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM user_settings WHERE user_id = $1', [req.user.id]);
    if (!result.rows.length) return res.json({ customFees: {}, walkthroughDone: false, journalCompletions: {} });
    const s = result.rows[0];
    res.json({ customFees: s.custom_fees||{}, walkthroughDone: s.walkthrough_done, journalCompletions: s.journal_completions||{} });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/settings', authMiddleware, async (req, res) => {
  try {
    const s = req.body;
    await pool.query(
      `INSERT INTO user_settings (user_id, custom_fees, walkthrough_done, journal_completions)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (user_id) DO UPDATE SET
         custom_fees=EXCLUDED.custom_fees, walkthrough_done=EXCLUDED.walkthrough_done,
         journal_completions=EXCLUDED.journal_completions`,
      [req.user.id, JSON.stringify(s.customFees||{}), s.walkthroughDone||false, JSON.stringify(s.journalCompletions||{})]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// MENTOR DASHBOARD ROUTES
// ═══════════════════════════════════

app.get('/api/mentor/students', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const students = await pool.query(
      `SELECT u.id, u.username, u.first_name, u.last_name, u.created_at,
        (SELECT COUNT(*) FROM trades t WHERE t.user_id = u.id) as trade_count,
        (SELECT COALESCE(SUM(t.pnl), 0) FROM trades t WHERE t.user_id = u.id) as total_pnl,
        (SELECT COUNT(*) FROM trades t WHERE t.user_id = u.id AND t.pnl > 0) as wins,
        (SELECT MAX(t.date) FROM trades t WHERE t.user_id = u.id) as last_trade_date,
        (SELECT MAX(dj.date) FROM daily_journals dj WHERE dj.user_id = u.id AND (dj.satisfaction > 0 OR dj.lessons != '')) as last_journal_date,
        (SELECT AVG(t.emotion_rating) FROM trades t WHERE t.user_id = u.id) as avg_emotion
       FROM users u WHERE u.is_mentor = FALSE ORDER BY u.username`
    );
    const result = students.rows.map(s => ({
      id: s.id, username: s.username, firstName: s.first_name||'', lastName: s.last_name||'', fullName: s.first_name&&s.last_name?s.first_name+' '+s.last_name:s.username, createdAt: s.created_at,
      tradeCount: parseInt(s.trade_count), totalPnl: parseFloat(s.total_pnl),
      wins: parseInt(s.wins), winRate: s.trade_count > 0 ? (s.wins / s.trade_count * 100) : 0,
      lastTradeDate: s.last_trade_date, lastJournalDate: s.last_journal_date,
      avgEmotion: s.avg_emotion ? parseFloat(s.avg_emotion) : 0
    }));
    res.json(result);
  } catch (err) {
    console.error('Mentor students error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/mentor/student/:id', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const userId = req.params.id;
    const [user, trades, journals, badges, milestones, roadmap, riskplan] = await Promise.all([
      pool.query('SELECT id, username, created_at FROM users WHERE id = $1', [userId]),
      pool.query('SELECT * FROM trades WHERE user_id = $1 ORDER BY date DESC', [userId]),
      pool.query('SELECT * FROM daily_journals WHERE user_id = $1', [userId]),
      pool.query('SELECT badge_id, earned_at FROM badges WHERE user_id = $1', [userId]),
      pool.query('SELECT milestone_id, earned_at FROM milestones WHERE user_id = $1', [userId]),
      pool.query('SELECT step_index, item_index FROM roadmap_progress WHERE user_id = $1', [userId]),
      pool.query('SELECT * FROM risk_plans WHERE user_id = $1', [userId])
    ]);

    if (!user.rows.length) return res.status(404).json({ error: 'Student not found' });

    const journalMap = {};
    journals.rows.forEach(r => { journalMap[r.date] = r; });
    const badgeMap = {};
    badges.rows.forEach(r => { badgeMap[r.badge_id] = r.earned_at; });
    const milestoneMap = {};
    milestones.rows.forEach(r => { milestoneMap[r.milestone_id] = r.earned_at; });

    res.json({
      user: user.rows[0],
      trades: trades.rows.map(r => ({
        id: r.id, date: r.date, ticker: r.ticker, direction: r.direction,
        pnl: parseFloat(r.pnl), strategy: r.strategy, emotionRating: r.emotion_rating,
        rulesFollowed: r.rules_followed || [], notes: r.notes
      })),
      journals: journalMap,
      badges: badgeMap,
      milestones: milestoneMap,
      roadmap: roadmap.rows,
      riskplan: riskplan.rows[0] || {}
    });
  } catch (err) {
    console.error('Mentor student detail error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/mentor/note', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const { studentId, date, note } = req.body;
    await pool.query(
      'INSERT INTO mentor_notes (mentor_id, student_id, date, note) VALUES ($1,$2,$3,$4)',
      [req.user.id, studentId, date, note]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/mentor/notes/:studentId', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM mentor_notes WHERE student_id = $1 ORDER BY created_at DESC',
      [req.params.studentId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// SERVE FRONTEND
// ═══════════════════════════════════

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'site', 'index.html'));
});

// ═══════════════════════════════════
// START SERVER
// ═══════════════════════════════════

async function start() {
  try {
    await initDB();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`SOA Trading Journal API running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();
