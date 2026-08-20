require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const { pool, initDB } = require('./db');
const { generateToken, authMiddleware, mentorOnly } = require('./auth');
const Anthropic = require('@anthropic-ai/sdk').default;

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
      screenshots: r.screenshots || [], importedFrom: r.imported_from, accountId: r.account_id
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
      `INSERT INTO trades (id, user_id, date, instrument, ticker, direction, entry_price, exit_price, quantity, stop_loss, pnl, fees, gross_pnl, strategy, emotion_rating, rules_followed, notes, screenshots, imported_from, account_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
       ON CONFLICT (id) DO UPDATE SET
         date=EXCLUDED.date, instrument=EXCLUDED.instrument, ticker=EXCLUDED.ticker,
         direction=EXCLUDED.direction, entry_price=EXCLUDED.entry_price, exit_price=EXCLUDED.exit_price,
         quantity=EXCLUDED.quantity, stop_loss=EXCLUDED.stop_loss, pnl=EXCLUDED.pnl,
         fees=EXCLUDED.fees, gross_pnl=EXCLUDED.gross_pnl, strategy=EXCLUDED.strategy,
         emotion_rating=EXCLUDED.emotion_rating, rules_followed=EXCLUDED.rules_followed,
         notes=EXCLUDED.notes, screenshots=EXCLUDED.screenshots, imported_from=EXCLUDED.imported_from,
         account_id=EXCLUDED.account_id`,
      [t.id, req.user.id, t.date, t.instrument||'futures', t.ticker, t.direction,
       t.entryPrice||'', t.exitPrice||'', t.quantity||'1', t.stopLoss||'',
       t.pnl||0, t.fees||0, t.grossPnl||t.pnl||0, t.strategy||'No Strategy Used',
       t.emotionRating||7, t.rulesFollowed||[], t.notes||'',
       t.screenshots||[], t.importedFrom||'', t.accountId||null]
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
          `INSERT INTO trades (id, user_id, date, instrument, ticker, direction, entry_price, exit_price, quantity, stop_loss, pnl, fees, gross_pnl, strategy, emotion_rating, rules_followed, notes, screenshots, imported_from, account_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
           ${conflictClause}`,
          [t.id, req.user.id, t.date, t.instrument||'futures', t.ticker, t.direction,
           t.entryPrice||'', t.exitPrice||'', t.quantity||'1', t.stopLoss||'',
           t.pnl||0, t.fees||0, t.grossPnl||t.pnl||0, t.strategy||'No Strategy Used',
           t.emotionRating||7, t.rulesFollowed||[], t.notes||'',
           t.screenshots||[], t.importedFrom||'', t.accountId||null]
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

app.delete('/api/trades', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM trades WHERE user_id = $1', [req.user.id]);
    res.json({ success: true, deleted: r.rowCount });
  } catch (err) { console.error('API error [DELETE /api/trades]:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/badges', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM badges WHERE user_id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (err) { console.error('API error [DELETE /api/badges]:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/milestones', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM milestones WHERE user_id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (err) { console.error('API error [DELETE /api/milestones]:', err.message); res.status(500).json({ error: 'Server error' }); }
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
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/badges/:badgeId', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO badges (user_id, badge_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, req.params.badgeId]
    );
    res.json({ success: true });
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/milestones', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT milestone_id, earned_at FROM milestones WHERE user_id = $1', [req.user.id]);
    const milestones = {};
    result.rows.forEach(r => { milestones[r.milestone_id] = r.earned_at; });
    res.json(milestones);
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/milestones/:milestoneId', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO milestones (user_id, milestone_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, req.params.milestoneId]
    );
    res.json({ success: true });
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
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
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
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
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
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
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
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
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
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
    const [user, trades, journals, badges, milestones, riskplan] = await Promise.all([
      pool.query('SELECT id, username, created_at FROM users WHERE id = $1', [userId]),
      pool.query('SELECT * FROM trades WHERE user_id = $1 ORDER BY date DESC', [userId]),
      pool.query('SELECT * FROM daily_journals WHERE user_id = $1', [userId]),
      pool.query('SELECT badge_id, earned_at FROM badges WHERE user_id = $1', [userId]),
      pool.query('SELECT milestone_id, earned_at FROM milestones WHERE user_id = $1', [userId]),
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
      riskplan: riskplan.rows[0] || {}
    });
  } catch (err) {
    console.error('Mentor student detail error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/mentor/insights', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const students = (await pool.query('SELECT id, username, first_name, last_name FROM users WHERE is_mentor = FALSE')).rows;
    if (!students.length) return res.json([]);
    const ids = students.map(s => s.id);
    const since = new Date(Date.now() - 14 * 864e5).toISOString().slice(0, 10);
    const week = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
    const [trades, plans, journals, mems, chats] = await Promise.all([
      pool.query('SELECT user_id, date, pnl FROM trades WHERE user_id = ANY($1) AND date >= $2', [ids, since]),
      pool.query('SELECT user_id, max_trades_per_day, max_loss_per_day FROM risk_plans WHERE user_id = ANY($1)', [ids]),
      pool.query("SELECT user_id, MAX(date) AS last FROM daily_journals WHERE user_id = ANY($1) AND (satisfaction > 0 OR lessons <> '') GROUP BY user_id", [ids]),
      pool.query("SELECT user_id, kind, content FROM coach_memory WHERE user_id = ANY($1) AND status = 'active' AND kind IN ('commitment','flag') ORDER BY id DESC", [ids]),
      pool.query('SELECT user_id, MAX(created_at) AS last FROM coach_messages WHERE user_id = ANY($1) GROUP BY user_id', [ids])
    ]);
    const planBy = {}; plans.rows.forEach(r => { planBy[r.user_id] = r; });
    const jBy = {}; journals.rows.forEach(r => { jBy[r.user_id] = String(r.last).slice(0, 10); });
    const cBy = {}; chats.rows.forEach(r => { cBy[r.user_id] = r.last; });
    const memBy = {}; mems.rows.forEach(r => { (memBy[r.user_id] = memBy[r.user_id] || []).push(r); });
    const byDay = {};
    trades.rows.forEach(t => {
      const d = normDateStr(t.date);
      if (d < week) return;
      const k = t.user_id + '|' + d;
      if (!byDay[k]) byDay[k] = { uid: t.user_id, n: 0, pnl: 0 };
      byDay[k].n++; byDay[k].pnl += parseFloat(t.pnl);
    });
    const out = students.map(st => {
      const plan = planBy[st.id] || {};
      let overTrade = 0, lossBreach = 0, tradedDays = 0;
      Object.values(byDay).forEach(d => {
        if (d.uid !== st.id) return;
        tradedDays++;
        if (plan.max_trades_per_day > 0 && d.n > plan.max_trades_per_day) overTrade++;
        if (plan.max_loss_per_day > 0 && d.pnl < -parseFloat(plan.max_loss_per_day)) lossBreach++;
      });
      const lastJ = jBy[st.id] || null;
      const gap = lastJ ? Math.floor((Date.now() - new Date(lastJ + 'T12:00:00').getTime()) / 864e5) : null;
      const mem = memBy[st.id] || [];
      return {
        id: st.id, username: st.username,
        name: (st.first_name && st.last_name) ? st.first_name + ' ' + st.last_name : st.username,
        tradedDays7: tradedDays, overTradeDays7: overTrade, lossBreachDays7: lossBreach,
        lastJournal: lastJ, journalGapDays: gap,
        commitments: mem.filter(m => m.kind === 'commitment').slice(0, 3).map(m => m.content),
        flags: mem.filter(m => m.kind === 'flag').slice(0, 3).map(m => m.content),
        lastCoachChat: cBy[st.id] || null
      };
    });
    res.json(out);
  } catch (err) { console.error('Mentor insights error:', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mentor/note', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const { studentId, date, note } = req.body;
    await pool.query(
      'INSERT INTO mentor_notes (mentor_id, student_id, date, note) VALUES ($1,$2,$3,$4)',
      [req.user.id, studentId, date, note]
    );
    res.json({ success: true });
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/mentor/notes/:studentId', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM mentor_notes WHERE student_id = $1 ORDER BY created_at DESC',
      [req.params.studentId]
    );
    res.json(result.rows);
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// AI JOURNAL ANALYSIS
// ═══════════════════════════════════

const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

const AI_SYSTEM_PROMPT = `You are an expert trading coach for the SOA (Solano Options Academy) trading system. You analyze a student's daily trading journal and provide direct, specific, actionable feedback.

The SOA system uses these strategies: SOA Levels, Fibonacci Golden Pocket, TFC (Trend Following Candle), and Orderblocks.

The 8 SOA trading rules are:
1. Followed max loss per trade
2. Followed max loss per day
3. Waited for confirmation candle
4. Traded at key level / liquidity zone
5. Proper position sizing
6. Did not resize mid-trade
7. Stopped at trade limit
8. Followed stop loss plan

Your coaching style:
- Be direct and specific — reference exact trades, numbers, and patterns
- Connect dots between emotion ratings, rule breaks, and P&L outcomes
- Compare today to recent history when patterns emerge
- If they had a pre-market plan, compare it to what actually happened
- One concrete recommendation for tomorrow, not five generic tips
- Speak like a mentor who reviewed their specific trades, not a template
- Use HTML formatting: <h4> for section headers, <strong> for emphasis, bullet points with •
- Keep it under 500 words — dense and useful, not padded`;

app.post('/api/ai/journal-analysis', authMiddleware, async (req, res) => {
  if (!anthropic) return res.status(503).json({ error: 'AI analysis not available' });

  try {
    const { dayTrades, journal, recentHistory, riskPlan, date } = req.body;
    if (!dayTrades || !dayTrades.length) return res.status(400).json({ error: 'No trades to analyze' });

    let prompt = `Analyze this trader's day for ${date}:\n\n`;
    prompt += `**Today's Trades:**\n`;
    dayTrades.forEach((t, i) => {
      prompt += `${i + 1}. ${t.ticker} ${t.direction} | Strategy: ${t.strategy || 'None'} | P&L: $${t.pnl} | Emotion: ${t.emotionRating}/10 | Rules followed: ${(t.rulesFollowed || []).join(', ') || 'none tagged'}${t.notes ? ' | Notes: ' + t.notes : ''}\n`;
    });

    const tp = dayTrades.reduce((s, t) => s + (t.pnl || 0), 0);
    const wins = dayTrades.filter(t => t.pnl > 0).length;
    prompt += `\nDay total: $${tp.toFixed(2)} | ${wins}W/${dayTrades.length - wins}L | ${dayTrades.length} trades\n`;

    if (riskPlan && riskPlan.maxLossPerTrade) {
      prompt += `\n**Risk Plan:** Account: $${riskPlan.accountSize || '?'} | Max loss/trade: $${riskPlan.maxLossPerTrade} | Max loss/day: $${riskPlan.maxLossPerDay} | Max trades/day: ${riskPlan.maxTradesPerDay || '?'}\n`;
    }

    if (journal) {
      if (journal.pmBias || journal.pmGoals || journal.pmLevels) {
        prompt += `\n**Pre-Market Plan:** Bias: ${journal.pmBias || 'not set'} | Goals: ${journal.pmGoals || 'not set'} | Key levels: ${journal.pmLevels || 'not set'} | Rules committed: ${(journal.pmRules || []).join(', ') || 'none'}\n`;
      }
      if (journal.emotions && journal.emotions.length) prompt += `Post-trading emotions: ${journal.emotions.join(', ')}\n`;
      if (journal.biases && journal.biases.length) prompt += `Biases experienced: ${journal.biases.join(', ')}\n`;
    }

    if (recentHistory && recentHistory.length) {
      prompt += `\n**Last 7 trading days:**\n`;
      recentHistory.forEach(d => {
        prompt += `${d.date}: ${d.tradeCount} trades, $${d.pnl.toFixed(2)}, ${d.winRate.toFixed(0)}% WR, ${d.avgEmotion.toFixed(1)} emo, ${d.compliance.toFixed(0)}% rules\n`;
      });
    }

    prompt += `\nGive your analysis in HTML format with <h4> section headers. Be specific to THIS trader's data.`;

    const pbA = await getPlaybook();
    const sysA = [{ type: 'text', text: AI_SYSTEM_PROMPT }];
    if (pbA) sysA.push({ type: 'text', text: '=== SOA PLAYBOOK (the mentor\'s system — analyze against this) ===\n' + pbA.text });
    sysA[sysA.length - 1].cache_control = { type: 'ephemeral' };
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 800,
      system: sysA,
      messages: [{ role: 'user', content: prompt }]
    });

    const analysis = message.content[0]?.text || '';
    res.json({ analysis });
  } catch (err) {
    console.error('AI analysis error:', err);
    res.status(500).json({ error: 'AI analysis failed' });
  }
});

// ═══════════════════════════════════
// SOA PLAYBOOK (shared coaching IP)
// ═══════════════════════════════════

async function getPlaybook() {
  try {
    const r = await pool.query("SELECT value FROM app_state WHERE key = 'soa_playbook'");
    if (!r.rows.length) return null;
    const p = JSON.parse(r.rows[0].value);
    return p && p.text ? p : null;
  } catch (e) { return null; }
}

app.get('/api/playbook', authMiddleware, async (req, res) => {
  try {
    const p = await getPlaybook();
    if (!p) return res.json({ text: '', updatedAt: null, source: '', chars: 0 });
    // Students only need to know it exists; mentors get the full text to edit.
    if (!req.user.is_mentor) return res.json({ text: '', updatedAt: p.updatedAt, source: p.source, chars: p.text.length });
    res.json({ text: p.text, updatedAt: p.updatedAt, source: p.source, chars: p.text.length });
  } catch (err) { console.error('API error [GET /api/playbook]:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/playbook', authMiddleware, mentorOnly, async (req, res) => {
  try {
    let text = String(req.body.text || '');
    let source = String(req.body.source || 'pasted');
    if (req.body.doc && req.body.doc.data) {
      const buf = Buffer.from(String(req.body.doc.data).replace(/^data:[^;]+;base64,/, ''), 'base64');
      if (buf.length > 8 * 1024 * 1024) return res.status(400).json({ error: 'Document too large (max 8MB)' });
      const nm = String(req.body.doc.name || 'document');
      text = /\.docx$/i.test(nm) ? docxToText(buf) : buf.toString('utf8');
      source = nm;
    }
    text = text.slice(0, 60000).trim();
    const payload = JSON.stringify({ text, updatedAt: new Date().toISOString(), source });
    await pool.query("INSERT INTO app_state (key, value) VALUES ('soa_playbook', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [payload]);
    res.json({ success: true, chars: text.length });
  } catch (err) {
    console.error('API error [POST /api/playbook]:', err.message);
    res.status(400).json({ error: 'Could not read that document — is it a valid .docx or text file?' });
  }
});

// ═══════════════════════════════════
// AI COACH CHAT
// ═══════════════════════════════════

const AdmZip = require('adm-zip');
function docxToText(buf) {
  const zip = new AdmZip(buf);
  const entry = zip.getEntry('word/document.xml');
  if (!entry) throw new Error('Not a valid .docx file');
  let xml = entry.getData().toString('utf8');
  xml = xml.replace(/<w:p[ >]/g, '\n<w:p ').replace(/<w:tab\/>/g, '\t');
  let text = xml.replace(/<[^>]+>/g, '');
  text = text.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'");
  return text.replace(/\n{3,}/g, '\n\n').trim();
}

const COACH_SYSTEM = `You are Delta — the AI trading coach inside the SOA Trading Journal, mentoring futures traders who follow the SOA system. Your name is Delta: the symbol of change, because your job is closing the gap between the trader someone is and the trader they're becoming. Refer to yourself as Delta when introducing yourself; otherwise just coach naturally.

SOA system context: strategies are SOA Levels, Fibonacci Golden Pocket, TFC, and Orderblocks. The 8 rules: followed max loss per trade; followed max loss per day; waited for confirmation candle; traded at key level / liquidity zone; proper position sizing; did not resize mid-trade; stopped at trade limit; followed stop loss plan.

You have tools that query the trader's REAL data. Rules for you:
- ALWAYS use tools before making any claim about their performance. Never invent or estimate statistics — cite exact figures from tool results.
- Use run_counterfactual to turn advice into dollars ("stopping at 3 trades/day would have made you $X more").
- Use remember(kind, content) to save durable facts the trader tells you or commits to. kinds: profile (who they are, account situation), playbook (their entry model / trading rules), commitment (things they commit to doing), flag (patterns you have flagged), question (open questions like withdrawal timing). Save conclusions, not chit-chat. Keep each memory under 200 characters.
- When your memory holds commitments, check them against real data and open with receipts when relevant — the trader asked you to hold them accountable.
- If the user attaches a chart image: analyze it conservatively. Describe only what is clearly visible. Never invent price levels or indicator values you cannot see. State uncertainty plainly. If trade metadata is provided, critique the specific trade against the SOA system.

SOA PLAYBOOK: if a playbook block is provided below, it is the mentor's own written trading system — the exact method these traders paid to learn. Treat it as authoritative. Judge every setup, entry, and rule break against it specifically (its criteria, its language, its thresholds) rather than generic trading advice, and quote its terminology back to the trader. When their behaviour contradicts it, say which part of the system they broke. If the trader asks something the playbook does not cover, answer from general SOA principles and say you are going beyond the written system.

DOCUMENTS: when the trader attaches a document, it is teach-the-coach material — usually their trading notes, entry model write-up, or summaries of past coaching conversations. Read it fully, extract every durable fact (entry model rules, risk/withdrawal plans, goals, known patterns and struggles, commitments), and save them with remember() using the right kind — batch ALL your remember() calls into a single response rather than one at a time. Then reply with a short bullet summary of what you learned and stored — do not quote the document back at length. If it conflicts with what you already know, ask about the conflict.

DAILY DEBRIEF: this is how the trader journals. When they want to talk about their day (or tap "Debrief my day"), first pull today's trades with query_trades for today's date and check get_journal_entries for today and open with a tight recap — P&L, what stands out, any rule breaks you can see. Then guide a short conversation, ONE question per message, about 3-5 exchanges: how the day actually felt (map what they say onto the allowed emotion terms), what was driving any bad decisions (map onto the allowed bias terms), the one lesson worth keeping, and tomorrow's plan. As you learn things, call save_journal to write their daily journal — you may call it multiple times as the picture fills in; it merges. When the debrief winds down, confirm plainly: "I've written today's journal — satisfaction X, [emotions], and your lesson is logged." Rate satisfaction 1-5 from how they describe the day (discipline quality, not just P&L). If they debrief a past day, use that date.

INTAKE: if your memory of this trader is empty, run a short interview before general coaching — ONE question per message, max five questions total: (1) account situation — personal or prop/funded, whose, payout rules; (2) their entry model — invite them to paste any written version; (3) the mistake they already know they keep making; (4) their 90-day goal; (5) what to hold them accountable for and whether they want blunt or gentle coaching. Save each answer with remember(). After the last question, summarize what you learned in 3-4 bullets and invite questions.

DATES: all dates are US Eastern trading days. The conversation history can span several days and is marked with session dates — never assume the last thing discussed was today. Before saying a journal already exists for today, confirm it with get_journal_entries for today's date rather than relying on the conversation. "Today" is the date given in the trader snapshot below — trust it over any other notion of the current date, and use it when calling save_journal for today's debrief.

Style: direct, specific, mentor voice. Short paragraphs. Plain text with **bold** for emphasis. No emoji, no headers. Under 250 words unless performing a requested audit.`;

const COACH_TOOLS = [
  { name: 'query_trades', description: 'Query the trader\'s real trade history with filters. Returns aggregates and up to 50 matching trades.',
    input_schema: { type: 'object', properties: {
      day_of_week: { type: 'string', description: 'Filter by weekday name, e.g. Friday' },
      date_from: { type: 'string', description: 'YYYY-MM-DD inclusive' },
      date_to: { type: 'string', description: 'YYYY-MM-DD inclusive' },
      strategy_contains: { type: 'string', description: 'Substring match on strategy; use "none" for untagged trades' },
      min_emotion: { type: 'number' }, max_emotion: { type: 'number' },
      result: { type: 'string', enum: ['win', 'loss'] },
      limit: { type: 'number', description: 'Max trades to return, default 20' }
    } } },
  { name: 'get_risk_plan', description: 'Get the trader\'s risk plan: account size/type, loss limits, max trades per day, personal rules.',
    input_schema: { type: 'object', properties: {} } },
  { name: 'get_journal_entries', description: 'Get daily journal entries (satisfaction 1-5, emotions, biases, lessons, observations, game plan).',
    input_schema: { type: 'object', properties: {
      date_from: { type: 'string' }, date_to: { type: 'string' }, limit: { type: 'number', description: 'default 10' } } } },
  { name: 'run_counterfactual', description: 'Compute what the trader\'s total P&L would have been under a hypothetical rule, vs actual.',
    input_schema: { type: 'object', properties: {
      rule: { type: 'string', enum: ['max_trades_per_day', 'min_emotion', 'skip_untagged', 'skip_day'], description: 'max_trades_per_day: only first N trades each day. min_emotion: only trades with emotion >= N. skip_untagged: drop trades with no strategy. skip_day: drop trades on a weekday (value = day name).' },
      value: { type: 'string', description: 'N for numeric rules, weekday name for skip_day' }
    }, required: ['rule'] } },
  { name: 'save_journal', description: 'Write or update the trader\'s daily journal for a date. Merges with any existing entry — only provided fields change. This is how debrief conversations become journal entries.',
    input_schema: { type: 'object', properties: {
      date: { type: 'string', description: 'YYYY-MM-DD' },
      satisfaction: { type: 'number', description: '1-5 stars, rate discipline quality of the day' },
      emotions: { type: 'array', items: { type: 'string', enum: ['Calm','Confident','Focused','Patient','Satisfied','Excited','Anxious','Frustrated','Impatient','Overwhelmed','Distracted','Disappointed'] } },
      biases: { type: 'array', items: { type: 'string', enum: ['Overtrading','Revenge Trading','FOMO','Impatience','Hesitation','Greed','Fear','Loss Aversion','Confirmation Bias','Anchoring Bias','Recency Bias','Sunk Cost Fallacy'] } },
      lessons: { type: 'string', description: 'The lesson learned, in the trader\'s own words where possible' },
      observations: { type: 'string', description: 'Market/behavior observations from the debrief' },
      gameplan: { type: 'string', description: 'Tomorrow\'s plan' }
    }, required: ['date'] } },
  { name: 'remember', description: 'Save a durable fact about this trader to your long-term memory.',
    input_schema: { type: 'object', properties: {
      kind: { type: 'string', enum: ['profile', 'playbook', 'commitment', 'flag', 'question'] },
      content: { type: 'string' }
    }, required: ['kind', 'content'] } }
];

const DOW = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
function normDateStr(d) {
  d = String(d || '');
  if (/^\d{4}-\d{2}-\d{2}/.test(d)) return d.slice(0, 10);
  let m = d.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m) return m[3] + '-' + m[1].padStart(2, '0') + '-' + m[2].padStart(2, '0');
  m = d.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2})$/);
  if (m) return '20' + m[3] + '-' + m[1].padStart(2, '0') + '-' + m[2].padStart(2, '0');
  return d.slice(0, 10);
}
function tradeDow(d) { const m = String(d).match(/^(\d{4})-(\d{2})-(\d{2})/); if (!m) return ''; return DOW[new Date(+m[1], +m[2]-1, +m[3]).getDay()]; }
function isUntagged(t) { return !t.strategy || t.strategy === 'No Strategy Used'; }
function aggr(rows) {
  const w = rows.filter(t => t.pnl > 0).length;
  return { count: rows.length, total_pnl: +rows.reduce((a,t) => a + t.pnl, 0).toFixed(2),
    win_rate: rows.length ? +(w / rows.length * 100).toFixed(1) : 0,
    avg_emotion: rows.length ? +(rows.reduce((a,t) => a + (t.emotion||5), 0) / rows.length).toFixed(1) : 0 };
}

async function coachTool(name, input, userId) {
  const tr = (await pool.query(
    'SELECT date, ticker, direction, pnl, strategy, emotion_rating, rules_followed, notes FROM trades WHERE user_id = $1 ORDER BY date ASC', [userId]
  )).rows.map(r => ({ date: normDateStr(r.date), ticker: r.ticker, direction: r.direction,
    pnl: parseFloat(r.pnl), strategy: r.strategy, emotion: r.emotion_rating,
    rules_followed: (r.rules_followed||[]).length, notes: (r.notes||'').slice(0,80) }));

  if (name === 'query_trades') {
    let rows = tr;
    if (input.day_of_week) rows = rows.filter(t => tradeDow(t.date).toLowerCase() === String(input.day_of_week).toLowerCase());
    if (input.date_from) rows = rows.filter(t => t.date >= input.date_from);
    if (input.date_to) rows = rows.filter(t => t.date <= input.date_to);
    if (input.strategy_contains) {
      const q = String(input.strategy_contains).toLowerCase();
      rows = q === 'none' ? rows.filter(isUntagged) : rows.filter(t => (t.strategy||'').toLowerCase().includes(q));
    }
    if (input.min_emotion != null) rows = rows.filter(t => (t.emotion||5) >= input.min_emotion);
    if (input.max_emotion != null) rows = rows.filter(t => (t.emotion||5) <= input.max_emotion);
    if (input.result === 'win') rows = rows.filter(t => t.pnl > 0);
    if (input.result === 'loss') rows = rows.filter(t => t.pnl < 0);
    const lim = Math.min(input.limit || 20, 50);
    return { ...aggr(rows), trades: rows.slice(-lim) };
  }
  if (name === 'get_risk_plan') {
    const r = (await pool.query('SELECT * FROM risk_plans WHERE user_id = $1', [userId])).rows[0];
    if (!r) return { note: 'No risk plan set yet.' };
    return { account_size: parseFloat(r.account_size), account_type: r.account_type,
      max_loss_per_trade: parseFloat(r.max_loss_per_trade), max_loss_per_day: parseFloat(r.max_loss_per_day),
      max_loss_per_week: parseFloat(r.max_loss_per_week), max_drawdown: parseFloat(r.max_drawdown),
      max_trades_per_day: r.max_trades_per_day, personal_rules: r.personal_rules };
  }
  if (name === 'get_journal_entries') {
    let q = 'SELECT date, satisfaction, emotions, biases, lessons, observations, gameplan FROM daily_journals WHERE user_id = $1';
    const ps = [userId];
    if (input.date_from) { ps.push(input.date_from); q += ` AND date >= $${ps.length}`; }
    if (input.date_to) { ps.push(input.date_to); q += ` AND date <= $${ps.length}`; }
    q += ' ORDER BY date DESC LIMIT ' + Math.min(input.limit || 10, 30);
    return { entries: (await pool.query(q, ps)).rows };
  }
  if (name === 'run_counterfactual') {
    const actual = aggr(tr).total_pnl;
    let kept = tr;
    if (input.rule === 'max_trades_per_day') {
      const n = parseInt(input.value) || 3; const per = {};
      kept = tr.filter(t => { per[t.date] = (per[t.date]||0) + 1; return per[t.date] <= n; });
    } else if (input.rule === 'min_emotion') {
      const n = parseInt(input.value) || 6; kept = tr.filter(t => (t.emotion||5) >= n);
    } else if (input.rule === 'skip_untagged') {
      kept = tr.filter(t => !isUntagged(t));
    } else if (input.rule === 'skip_day') {
      const d = String(input.value||'Friday').toLowerCase(); kept = tr.filter(t => tradeDow(t.date).toLowerCase() !== d);
    }
    const hypo = aggr(kept);
    return { actual_pnl: actual, hypothetical_pnl: hypo.total_pnl, difference: +(hypo.total_pnl - actual).toFixed(2),
      trades_kept: hypo.count, trades_dropped: tr.length - hypo.count, hypothetical_win_rate: hypo.win_rate };
  }
  if (name === 'save_journal') {
    const d = String(input.date || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return { error: 'invalid date' };
    const cur = (await pool.query('SELECT * FROM daily_journals WHERE user_id = $1 AND date = $2', [userId, d])).rows[0] || {};
    const sat = input.satisfaction != null ? Math.max(1, Math.min(5, Math.round(input.satisfaction))) : (cur.satisfaction || 0);
    const emo = Array.isArray(input.emotions) && input.emotions.length ? input.emotions.slice(0, 6) : (cur.emotions || []);
    const bia = Array.isArray(input.biases) && input.biases.length ? input.biases.slice(0, 6) : (cur.biases || []);
    const les = input.lessons != null ? String(input.lessons).slice(0, 2000) : (cur.lessons || '');
    const obs = input.observations != null ? String(input.observations).slice(0, 2000) : (cur.observations || '');
    const gp = input.gameplan != null ? String(input.gameplan).slice(0, 2000) : (cur.gameplan || '');
    await pool.query(
      `INSERT INTO daily_journals (user_id, date, satisfaction, emotions, biases, lessons, observations, gameplan)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (user_id, date) DO UPDATE SET
         satisfaction=EXCLUDED.satisfaction, emotions=EXCLUDED.emotions, biases=EXCLUDED.biases,
         lessons=EXCLUDED.lessons, observations=EXCLUDED.observations, gameplan=EXCLUDED.gameplan`,
      [userId, d, sat, emo, bia, les, obs, gp]);
    return { saved: true, date: d };
  }
  if (name === 'remember') {
    const kinds = ['profile','playbook','commitment','flag','question'];
    if (!kinds.includes(input.kind)) return { error: 'invalid kind' };
    await pool.query('INSERT INTO coach_memory (user_id, kind, content) VALUES ($1,$2,$3)',
      [userId, input.kind, String(input.content).slice(0, 400)]);
    return { saved: true };
  }
  return { error: 'unknown tool' };
}

app.get('/api/coach/history', authMiddleware, async (req, res) => {
  try {
    const msgs = (await pool.query(
      'SELECT role, content, has_image FROM coach_messages WHERE user_id = $1 ORDER BY id DESC LIMIT 40', [req.user.id]
    )).rows.reverse();
    const mem = (await pool.query(
      "SELECT COUNT(*)::int AS c FROM coach_memory WHERE user_id = $1 AND status = 'active'", [req.user.id]
    )).rows[0].c;
    res.json({ messages: msgs, memoryCount: mem });
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/coach/chat', authMiddleware, async (req, res) => {
  if (!anthropic) return res.status(503).json({ error: 'Coach is not configured yet' });
  try {
    const { message, image, doc } = req.body;
    if (!message && !image && !doc) return res.status(400).json({ error: 'Empty message' });

    const used = (await pool.query(
      "SELECT COUNT(*)::int AS c FROM coach_messages WHERE user_id = $1 AND role = 'user' AND created_at > NOW() - INTERVAL '24 hours'", [req.user.id]
    )).rows[0].c;
    if (!req.user.is_mentor && used >= 30) return res.status(429).json({ error: 'Daily coach limit reached — back tomorrow.' });

    const memRows = (await pool.query(
      "SELECT kind, content, created_at FROM coach_memory WHERE user_id = $1 AND status = 'active' ORDER BY id ASC LIMIT 60", [req.user.id]
    )).rows;
    const hist = (await pool.query(
      'SELECT role, content, created_at FROM coach_messages WHERE user_id = $1 ORDER BY id DESC LIMIT 20', [req.user.id]
    )).rows.reverse();

    const stats = (await pool.query(
      `SELECT COUNT(*)::int AS n, COALESCE(SUM(pnl),0) AS pnl,
        COUNT(*) FILTER (WHERE pnl > 0)::int AS wins,
        COUNT(*) FILTER (WHERE strategy IS NULL OR strategy = 'No Strategy Used')::int AS untagged
       FROM trades WHERE user_id = $1`, [req.user.id]
    )).rows[0];

    let dyn = `Trader snapshot: ${stats.n} trades, net P&L $${parseFloat(stats.pnl).toFixed(2)}, ` +
      `${stats.n ? (stats.wins / stats.n * 100).toFixed(1) : 0}% win rate, ${stats.untagged} untagged trades. Today: ${etTodayStr()} (${etParts().weekday}, US Eastern trading day).\n`;
    dyn += memRows.length
      ? 'Your memory of this trader:\n' + memRows.map(m => `- [${m.kind}] ${m.content} (${String(m.created_at).slice(0,10)})`).join('\n')
      : 'Your memory of this trader is EMPTY — run the intake interview.';

    const etDay = (d) => {
      const f = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', weekday: 'short', month: 'short', day: 'numeric' });
      return f.format(new Date(d));
    };
    const todayKey = etTodayStr();
    const etKey = (d) => {
      const p = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit' })
        .formatToParts(new Date(d)).reduce((a, x) => (a[x.type] = x.value, a), {});
      return `${p.year}-${p.month}-${p.day}`;
    };
    const messages = [];
    let lastKey = null;
    for (const h of hist) {
      const k = h.created_at ? etKey(h.created_at) : todayKey;
      let text = h.content;
      if (k !== lastKey) {
        text = `[${k === todayKey ? 'Today, ' + etDay(h.created_at || new Date()) : 'Earlier session — ' + etDay(h.created_at)}]\n` + text;
        lastKey = k;
      }
      if (messages.length && messages[messages.length-1].role === h.role) messages[messages.length-1].content += '\n' + text;
      else messages.push({ role: h.role, content: text });
    }
    if (lastKey && lastKey !== todayKey) messages.push({ role: 'user', content: `[New session — today is ${todayKey}. Everything above happened on an earlier day.]` });
    let userText = message || (doc ? 'I\'ve attached a document for you to learn from.' : 'Please analyze this chart screenshot.');
    let docNote = '';
    if (doc && doc.data) {
      try {
        const buf = Buffer.from(String(doc.data).replace(/^data:[^;]+;base64,/, ''), 'base64');
        if (buf.length > 8 * 1024 * 1024) return res.status(400).json({ error: 'Document too large (max 8MB)' });
        const nm = String(doc.name || 'document');
        let text;
        if (/\.docx$/i.test(nm)) text = docxToText(buf);
        else text = buf.toString('utf8');
        text = text.slice(0, 60000);
        docNote = ' [document attached: ' + nm + ']';
        userText = userText + '\n\n=== ATTACHED DOCUMENT: ' + nm + ' ===\n' + text + '\n=== END DOCUMENT ===';
      } catch (e) {
        return res.status(400).json({ error: 'Could not read that document — is it a valid .docx or text file?' });
      }
    }
    let userContent = userText;
    if (image) {
      const m = String(image).match(/^data:(image\/\w+);base64,(.+)$/s);
      if (m) userContent = [
        { type: 'image', source: { type: 'base64', media_type: m[1], data: m[2] } },
        { type: 'text', text: userText }
      ];
    }
    if (messages.length && messages[messages.length-1].role === 'user') messages.push({ role: 'assistant', content: '(continued)' });
    messages.push({ role: 'user', content: userContent });

    await pool.query('INSERT INTO coach_messages (user_id, role, content, has_image) VALUES ($1,$2,$3,$4)',
      [req.user.id, 'user', (message || 'Document upload') + (image ? ' [chart screenshot attached]' : '') + docNote, !!image]);

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');
    let reply = '';
    const emit = (d) => { reply += d; res.write(d); };
    const pb = await getPlaybook();
    const sys = [{ type: 'text', text: COACH_SYSTEM }];
    if (pb) sys.push({ type: 'text', text: '=== SOA PLAYBOOK (the mentor\'s system — coach against this) ===\n' + pb.text });
    sys[sys.length - 1].cache_control = { type: 'ephemeral' };
    sys.push({ type: 'text', text: dyn });
    let finished = false;
    for (let i = 0; i < 10; i++) {
      const stream = anthropic.messages.stream({
        model: 'claude-sonnet-4-6', max_tokens: 2000,
        system: sys, tools: COACH_TOOLS, messages
      });
      stream.on('text', emit);
      const resp = await stream.finalMessage();
      const toolUses = resp.content.filter(b => b.type === 'tool_use');
      if (resp.stop_reason !== 'tool_use' || !toolUses.length) { finished = true; break; }
      messages.push({ role: 'assistant', content: resp.content });
      const results = [];
      for (const tu of toolUses) {
        let out;
        try { out = await coachTool(tu.name, tu.input || {}, req.user.id); }
        catch (e) { console.error('Coach tool error:', tu.name, e.message); out = { error: 'tool failed: ' + e.message }; }
        results.push({ type: 'tool_result', tool_use_id: tu.id, content: JSON.stringify(out).slice(0, 12000) });
      }
      messages.push({ role: 'user', content: results });
    }
    if (!finished) {
      try {
        const fin = anthropic.messages.stream({
          model: 'claude-sonnet-4-6', max_tokens: 1500,
          system: sys, tools: COACH_TOOLS, tool_choice: { type: 'none' },
          messages: [...messages, { role: 'user', content: 'Wrap up now in plain text: summarize what you just did and learned (including anything you saved to memory), and what the trader should know or do next.' }]
        });
        fin.on('text', emit);
        await fin.finalMessage();
      } catch (e) { console.error('Coach wrap-up error:', e.message); }
    }
    if (!reply) { reply = 'I processed that but could not compose a reply — ask me what I saved.'; res.write(reply); }
    await pool.query('INSERT INTO coach_messages (user_id, role, content) VALUES ($1,$2,$3)', [req.user.id, 'assistant', reply]);
    res.end();
  } catch (err) {
    console.error('Coach chat error:', err);
    if (res.headersSent) { try { res.write('\n\n**The coach hit an error — try that again.**'); res.end(); } catch (e) {} }
    else res.status(500).json({ error: 'Coach is unavailable right now' });
  }
});

app.get('/api/coach/memory', authMiddleware, async (req, res) => {
  try {
    const rows = (await pool.query(
      "SELECT id, kind, content, created_at FROM coach_memory WHERE user_id = $1 AND status = 'active' ORDER BY kind, id DESC LIMIT 100", [req.user.id]
    )).rows;
    res.json(rows);
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/coach/memory/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE coach_memory SET status = 'deleted' WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// PROP ACCOUNTS & TRADOVATE SYNC
// ═══════════════════════════════════

const crypto = require('crypto');
const ENC_KEY = crypto.scryptSync(process.env.JWT_SECRET || 'soa-dev-secret', 'soa-acct-salt', 32);
function encSecret(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return iv.toString('hex') + ':' + c.getAuthTag().toString('hex') + ':' + enc.toString('hex');
}
function decSecret(blob) {
  const [iv, tag, data] = String(blob).split(':');
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(iv, 'hex'));
  d.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([d.update(Buffer.from(data, 'hex')), d.final()]).toString('utf8');
}

function acctRow(r) {
  return { id: r.id, name: r.name, firm: r.firm, env: r.env, brokerIds: r.broker_ids,
    tvUser: r.tv_user, hasCredentials: !!(r.tv_user && r.tv_pass_enc),
    phase: r.phase, profitTarget: parseFloat(r.profit_target), maxDrawdown: parseFloat(r.max_drawdown),
    minDays: r.min_days, consistencyPct: r.consistency_pct, payoutMin: parseFloat(r.payout_min),
    lastSync: r.last_sync };
}

app.get('/api/accounts', authMiddleware, async (req, res) => {
  try {
    const rows = (await pool.query('SELECT * FROM accounts WHERE user_id = $1 ORDER BY id', [req.user.id])).rows;
    res.json(rows.map(acctRow));
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/accounts', authMiddleware, async (req, res) => {
  try {
    const a = req.body;
    if (!a.name) return res.status(400).json({ error: 'Account name required' });
    const passEnc = a.tvPass ? encSecret(a.tvPass) : '';
    if (a.id) {
      const cur = (await pool.query('SELECT tv_pass_enc FROM accounts WHERE id = $1 AND user_id = $2', [a.id, req.user.id])).rows[0];
      if (!cur) return res.status(404).json({ error: 'Account not found' });
      await pool.query(
        `UPDATE accounts SET name=$1, firm=$2, env=$3, broker_ids=$4, tv_user=$5, tv_pass_enc=$6,
         phase=$7, profit_target=$8, max_drawdown=$9, min_days=$10, consistency_pct=$11, payout_min=$12
         WHERE id=$13 AND user_id=$14`,
        [a.name, a.firm||'', a.env==='live'?'live':'demo', a.brokerIds||'', a.tvUser||'',
         a.tvPass ? passEnc : cur.tv_pass_enc,
         a.phase||'eval', a.profitTarget||0, a.maxDrawdown||0, a.minDays||0, a.consistencyPct||0, a.payoutMin||0,
         a.id, req.user.id]);
      res.json({ success: true, id: a.id });
    } else {
      const r = await pool.query(
        `INSERT INTO accounts (user_id, name, firm, env, broker_ids, tv_user, tv_pass_enc, phase, profit_target, max_drawdown, min_days, consistency_pct, payout_min)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
        [req.user.id, a.name, a.firm||'', a.env==='live'?'live':'demo', a.brokerIds||'', a.tvUser||'', passEnc,
         a.phase||'eval', a.profitTarget||0, a.maxDrawdown||0, a.minDays||0, a.consistencyPct||0, a.payoutMin||0]);
      res.json({ success: true, id: r.rows[0].id });
    }
  } catch (err) { console.error('Account save error:', err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/accounts/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE trades SET account_id = NULL WHERE account_id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    await pool.query('DELETE FROM accounts WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

// ---- Tradovate sync ----
const TV_TICK_VALUES = {ES:12.50,MES:1.25,NQ:5.00,MNQ:0.50,YM:5.00,MYM:0.50,RTY:5.00,M2K:0.50,CL:10.00,MCL:1.00,GC:10.00,MGC:1.00,SI:25.00,NG:10.00};
const TV_TICK_SIZES = {ES:0.25,MES:0.25,NQ:0.25,MNQ:0.25,YM:1.00,MYM:1.00,RTY:0.10,M2K:0.10,CL:0.01,MCL:0.01,GC:0.10,MGC:0.10,SI:0.005,NG:0.001};
const TV_RT_FEES = {ES:5.00,NQ:5.00,MES:1.90,MNQ:1.90,YM:5.00,MYM:1.90,RTY:5.00,M2K:1.90,CL:5.00,MCL:1.90,GC:5.00,MGC:1.90,SI:5.00,NG:5.00};
function tvProduct(contractName) {
  const m = String(contractName).match(/^([A-Z]+?)[FGHJKMNQUVXZ]\d+$/i);
  return m ? m[1].toUpperCase() : String(contractName).replace(/[0-9]+$/, '').toUpperCase();
}

async function tvFetch(base, path, token) {
  const r = await fetch(base + path, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
  if (!r.ok) throw new Error(`Tradovate ${path} failed (${r.status})`);
  return r.json();
}

async function tvAuth(base, username, password) {
  if (!process.env.TRADOVATE_CID || !process.env.TRADOVATE_SEC) {
    throw new Error('Tradovate API keys are not configured on the server (TRADOVATE_CID / TRADOVATE_SEC).');
  }
  const r = await fetch(base + '/auth/accesstokenrequest', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: username, password,
      appId: 'SOA Journal', appVersion: '1.0',
      cid: parseInt(process.env.TRADOVATE_CID), sec: process.env.TRADOVATE_SEC,
      deviceId: 'soa-' + crypto.createHash('md5').update(username).digest('hex').slice(0, 16)
    })
  });
  const data = await r.json().catch(() => ({}));
  if (data['p-ticket']) throw new Error('Tradovate is asking for a captcha — log into Tradovate once in a browser, then retry the sync.');
  if (!r.ok || !data.accessToken) throw new Error(data.errorText || 'Tradovate login failed — check the username and password.');
  return data.accessToken;
}

app.post('/api/accounts/:id/sync', authMiddleware, async (req, res) => {
  try {
    const acct = (await pool.query('SELECT * FROM accounts WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])).rows[0];
    if (!acct) return res.status(404).json({ error: 'Account not found' });
    if (!acct.tv_user || !acct.tv_pass_enc) return res.status(400).json({ error: 'Add Tradovate credentials to this account first.' });

    const base = acct.env === 'live' ? 'https://live.tradovateapi.com/v1' : 'https://demo.tradovateapi.com/v1';
    const token = await tvAuth(base, acct.tv_user, decSecret(acct.tv_pass_enc));

    const tvAccounts = await tvFetch(base, '/account/list', token);
    const wanted = (acct.broker_ids || '').split(',').map(x => x.trim()).filter(Boolean);
    const matched = tvAccounts.filter(a => !wanted.length || wanted.some(w => (a.name || '').includes(w)));
    if (!matched.length) return res.status(400).json({ error: 'No Tradovate accounts matched. Check the linked account IDs (' + tvAccounts.map(a => a.name).join(', ') + ')' });
    const acctIds = new Set(matched.map(a => a.id));

    const [orders, fills] = await Promise.all([
      tvFetch(base, '/order/list', token),
      tvFetch(base, '/fill/list', token)
    ]);
    const orderById = {};
    orders.forEach(o => { orderById[o.id] = o; });
    const relevant = fills.filter(f => { const o = orderById[f.orderId]; return o && acctIds.has(o.accountId); });

    const contractIds = [...new Set(relevant.map(f => f.contractId).filter(Boolean))];
    const contractName = {};
    for (let i = 0; i < contractIds.length; i += 20) {
      const chunk = contractIds.slice(i, i + 20);
      const items = await tvFetch(base, '/contract/items?ids=' + chunk.join(','), token);
      (Array.isArray(items) ? items : []).forEach(c => { contractName[c.id] = c.name; });
    }

    relevant.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const byProduct = {};
    relevant.forEach(f => {
      const product = tvProduct(contractName[f.contractId] || '');
      if (!byProduct[product]) byProduct[product] = [];
      byProduct[product].push(f);
    });

    const rts = [];
    Object.entries(byProduct).forEach(([product, pf]) => {
      let pos = 0, entries = [];
      pf.forEach(f => {
        const qty = f.qty || 1, price = f.price || 0;
        const isBuy = (f.action || '').toLowerCase() === 'buy';
        const signed = isBuy ? qty : -qty;
        const date = String(f.timestamp).slice(0, 10);
        if (pos === 0) { entries = [{ qty, price }]; pos = signed; }
        else if ((pos > 0 && !isBuy) || (pos < 0 && isBuy)) {
          const closeQty = Math.min(Math.abs(pos), qty);
          const ep = entries.reduce((s, e) => s + e.price * e.qty, 0) / entries.reduce((s, e) => s + e.qty, 0);
          const dir = pos > 0 ? 'Long' : 'Short';
          const tv = TV_TICK_VALUES[product] || 1, ts = TV_TICK_SIZES[product] || 0.01;
          const gross = (dir === 'Long' ? (price - ep) : (ep - price)) / ts * tv * closeQty;
          const fee = (TV_RT_FEES[product] || 2.0) * closeQty;
          rts.push({ date, product, direction: dir, entryPrice: ep.toFixed(2), exitPrice: price.toFixed(2),
            quantity: closeQty, grossPnl: Math.round(gross * 100) / 100, fees: Math.round(fee * 100) / 100,
            pnl: Math.round((gross - fee) * 100) / 100 });
          const rem = Math.abs(pos) - closeQty;
          if (rem <= 0) { pos = 0; entries = []; const left = qty - closeQty; if (left > 0) { entries = [{ qty: left, price }]; pos = isBuy ? left : -left; } }
          else pos = pos > 0 ? rem : -rem;
        } else { entries.push({ qty, price }); pos += signed; }
      });
    });

    const existing = new Set((await pool.query(
      'SELECT date, ticker, direction, entry_price, exit_price, quantity, pnl FROM trades WHERE user_id = $1', [req.user.id]
    )).rows.map(t => [String(t.date).slice(0,10), t.ticker, t.direction, t.entry_price, t.exit_price, t.quantity, Math.round(parseFloat(t.pnl))].join('|')));

    let imported = 0;
    for (const t of rts) {
      const sig = [t.date, t.product, t.direction, t.entryPrice, t.exitPrice, String(t.quantity), Math.round(t.pnl)].join('|');
      if (existing.has(sig)) continue;
      existing.add(sig);
      const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
      await pool.query(
        `INSERT INTO trades (id, user_id, date, instrument, ticker, direction, entry_price, exit_price, quantity, stop_loss, pnl, fees, gross_pnl, strategy, emotion_rating, rules_followed, notes, screenshots, imported_from, account_id)
         VALUES ($1,$2,$3,'futures',$4,$5,$6,$7,$8,'',$9,$10,$11,'No Strategy Used',7,'{}','Synced from Tradovate','{}','tradovate',$12)`,
        [id, req.user.id, t.date, t.product, t.direction, t.entryPrice, t.exitPrice, String(t.quantity), t.pnl, t.fees, t.grossPnl, acct.id]);
      imported++;
    }
    await pool.query('UPDATE accounts SET last_sync = NOW() WHERE id = $1', [acct.id]);
    res.json({ success: true, imported, matched: rts.length, accounts: matched.map(a => a.name) });
  } catch (err) {
    console.error('Tradovate sync error:', err.message);
    res.status(502).json({ error: err.message || 'Sync failed' });
  }
});

// ═══════════════════════════════════
// DISCORD ROLL CALL
// ═══════════════════════════════════

function etTodayStr(){const p=etParts();return `${p.year}-${p.month}-${p.day}`}
function etParts() {
  const f = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', hourCycle: 'h23',
    weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  const parts = {};
  f.formatToParts(new Date()).forEach(x => { parts[x.type] = x.value; });
  if (parts.hour === '24') parts.hour = '00'; // ICU h24 quirk: midnight as "24"
  return parts;
}

async function postRollCall() {
  const hook = process.env.DISCORD_ROLLCALL_WEBHOOK;
  if (!hook) return { error: 'DISCORD_ROLLCALL_WEBHOOK is not set in the environment' };
  const p = etParts();
  const dateKey = `${p.year}-${p.month}-${p.day}`;
  const users = (await pool.query('SELECT id, username, first_name FROM users ORDER BY is_mentor DESC, id')).rows;
  if (!users.length) return { error: 'No users yet' };
  const done = (await pool.query(
    "SELECT DISTINCT user_id FROM daily_journals WHERE date = $1 AND (satisfaction > 0 OR lessons <> '')", [dateKey]
  )).rows.map(r => r.user_id);
  const journaled = users.filter(u => done.includes(u.id));
  const nm = u => u.first_name || u.username;
  let names = journaled.slice(0, 30).map(u => '✅ ' + nm(u)).join(' · ');
  if (journaled.length > 30) names += ` · +${journaled.length - 30} more`;
  const desc = (journaled.length
    ? names + `\n\n**${journaled.length} of ${users.length}** traders debriefed today.`
    : `**0 of ${users.length}** journals in — the room went quiet today.`)
    + '\n\nNot on the list? Go to https://app.simplyoptionsacademy.com to get your journal done.';
  const embed = {
    title: `📋 Today's Journals — ${p.weekday} ${p.month}/${p.day}`,
    description: desc,
    color: journaled.length >= users.length / 2 ? 0x6fb083 : 0xc0a55f,
    footer: { text: 'SOA Trading Journal · debrief with Delta in 2 minutes' }
  };
  const r = await fetch(hook, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'SOA Journal', embeds: [embed] }) });
  if (!r.ok) return { error: 'Discord returned ' + r.status };
  return { success: true, journaled: journaled.length, of: users.length };
}

function startRollCall() {
  setInterval(async () => {
    try {
      const p = etParts();
      if (p.weekday === 'Sat' || p.weekday === 'Sun') return;
      const mins = parseInt(p.hour, 10) * 60 + parseInt(p.minute, 10);
      if (mins < 17 * 60 + 30) return; // fire on any tick from 5:30pm ET onward
      const dateKey = `${p.year}-${p.month}-${p.day}`;
      const last = (await pool.query("SELECT value FROM app_state WHERE key = 'rollcall_last'")).rows[0];
      if (last && last.value === dateKey) return;
      const out = await postRollCall();
      if (out.error) { console.error('Roll call:', out.error); return; }
      await pool.query("INSERT INTO app_state (key, value) VALUES ('rollcall_last', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [dateKey]);
      console.log('Roll call posted:', out.journaled + '/' + out.of);
    } catch (e) { console.error('Roll call error:', e.message); }
  }, 60000);
}

app.post('/api/mentor/rollcall', authMiddleware, mentorOnly, async (req, res) => {
  try {
    const out = await postRollCall();
    if (out.error) return res.status(400).json(out);
    res.json(out);
  } catch (err) { console.error('API error [' + req.method + ' ' + req.path + ']:', err.message); res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════
// SERVE FRONTEND
// ═══════════════════════════════════

app.get('/api/health', (req, res) => {
  res.json({ ok: true, db: dbReady, uptime: Math.round(process.uptime()) });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'site', 'index.html'));
});

// ═══════════════════════════════════
// START SERVER
// ═══════════════════════════════════

let dbReady = false;
async function start() {
  // Listen first so the healthcheck passes and deploy logs stay inspectable
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOA Trading Journal API running on port ${PORT}`);
  });
  const tryInit = async (attempt) => {
    try {
      await initDB();
      dbReady = true;
      console.log('Database ready');
    } catch (err) {
      console.error(`Database init failed (attempt ${attempt}):`, err.message);
      if (attempt < 20) setTimeout(() => tryInit(attempt + 1), 15000);
    }
  };
  tryInit(1);
  startRollCall();
}

start();
