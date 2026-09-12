const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));

const sessionStore = new pgSession({
  pool,
  tableName: 'user_sessions',
  createTableIfMissing: true
});
app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'change-this-session-secret-before-production',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false,
  maxAge: 0
}));

let dbReady = false;

async function initDatabase() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members(
      id SERIAL PRIMARY KEY,
      member_id VARCHAR(40) UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      phone VARCHAR(40), email TEXT,
      state TEXT, lga TEXT, gender VARCHAR(30), date_of_birth DATE, address TEXT,
      emergency_contact TEXT, emergency_phone VARCHAR(40), blood_group VARCHAR(10),
      qualification TEXT, first_aid_level TEXT, unit TEXT, year_of_entry VARCHAR(10),
      rank TEXT, office_description TEXT, photo_url TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), approved_at TIMESTAMPTZ,
      last_login_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS admins(
      id SERIAL PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role VARCHAR(30) DEFAULT 'approver', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS member_login_codes(
      id SERIAL PRIMARY KEY, member_id INTEGER REFERENCES members(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INTEGER DEFAULT 0,
      used_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id SERIAL PRIMARY KEY, admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
      action VARCHAR(80) NOT NULL, member_id INTEGER REFERENCES members(id) ON DELETE SET NULL,
      details TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS members_status_idx ON members(status);
    CREATE INDEX IF NOT EXISTS members_name_idx ON members(lower(full_name));
    CREATE INDEX IF NOT EXISTS members_email_idx ON members(lower(email));
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at DESC);
  `);
  const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM admins');
  if (rows[0].count === 0) {
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'FityanulAdmin2026!';
    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO admins(username,password_hash,role) VALUES($1,$2,$3)', [username, hash, 'super_admin']);
    console.log('Initial admin account created from environment/default configuration.');
  }
  dbReady = true;
  console.log('Database ready');
}
initDatabase().catch(err => console.error('Database initialization failed:', err.message));

const requireDb = (req, res, next) => dbReady ? next() : res.status(503).json({ error: 'Database is still connecting. Please try again shortly.' });
const requireAdmin = (req, res, next) => req.session.admin ? next() : res.status(401).json({ error: 'Admin login required' });
const requireMember = (req, res, next) => req.session.member ? next() : res.status(401).json({ error: 'Member login required' });
const normalizeEmail = value => String(value || '').trim().toLowerCase();
const clean = value => String(value ?? '').trim();
const makeMemberId = () => 'FNI-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
const hashCode = code => crypto.createHash('sha256').update(String(code)).digest('hex');
const makeCode = () => String(crypto.randomInt(100000, 1000000));

async function audit(req, action, memberId = null, details = '') {
  try {
    await pool.query('INSERT INTO audit_logs(admin_id,action,member_id,details) VALUES($1,$2,$3,$4)', [req.session.admin?.id || null, action, memberId, details]);
  } catch (err) { console.error('Audit write failed:', err.message); }
}

async function sendMemberCode(email, name, code) {
  if (!process.env.RESEND_API_KEY || !process.env.RESEND_FROM_EMAIL) {
    throw new Error('Member email service is not configured yet.');
  }
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL,
      to: [email],
      subject: 'Your Fityanul Islam member login code',
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto"><h2>First Aid Group Initiative Fityanul Islam of Nigeria</h2><p>Assalamu alaikum ${name},</p><p>Your one-time member login code is:</p><div style="font-size:34px;font-weight:700;letter-spacing:8px;padding:18px;background:#eef3f9;text-align:center">${code}</div><p>This code expires in 10 minutes and can only be used once.</p></div>`
    })
  });
  if (!response.ok) throw new Error('Unable to send verification email.');
}

app.get('/api/health', (req, res) => res.json({ ok: true, database: dbReady, email_service: Boolean(process.env.RESEND_API_KEY && process.env.RESEND_FROM_EMAIL) }));

// Registration: every successful new application is explicitly stored as PENDING.
app.post('/api/register', requireDb, async (req, res) => {
  const d = req.body || {};
  const fullName = clean(d.full_name);
  const email = normalizeEmail(d.email);
  const phone = clean(d.phone);
  const emergencyPhone = clean(d.emergency_phone);
  try {
    if (!fullName) return res.status(400).json({ error: 'Full name is required.' });
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'A valid email address is required.' });
    if (!phone) return res.status(400).json({ error: 'Phone number is required.' });
    if (!d.photo_url || !String(d.photo_url).startsWith('data:image/')) return res.status(400).json({ error: 'Passport photograph is required.' });
    if (String(d.photo_url).length > 1500000) return res.status(413).json({ error: 'Passport photograph is too large. Please choose a smaller photo.' });
    if (!clean(d.state) || !clean(d.lga) || !clean(d.gender) || !clean(d.date_of_birth)) return res.status(400).json({ error: 'Please complete all required personal details.' });
    if (!clean(d.address) || !clean(d.emergency_contact) || !emergencyPhone) return res.status(400).json({ error: 'Address and emergency contact details are required.' });

    const existing = await pool.query(`SELECT id,status FROM members WHERE lower(email)=lower($1) AND status IN ('pending','approved') ORDER BY id DESC LIMIT 1`, [email]);
    if (existing.rows[0]) return res.status(409).json({ error: 'This email is already registered. If you already applied, please wait for administrator approval.' });

    const memberId = makeMemberId();
    const result = await pool.query(`
      INSERT INTO members(member_id,full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,year_of_entry,photo_url,status)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'pending') RETURNING member_id,status,created_at
    `, [memberId, fullName, phone, email, clean(d.state), clean(d.lga), clean(d.gender), d.date_of_birth || null, clean(d.address), clean(d.emergency_contact), emergencyPhone, clean(d.blood_group), clean(d.qualification), clean(d.first_aid_level), clean(d.unit), clean(d.year_of_entry), d.photo_url]);
    console.log('Member registration saved as pending:', result.rows[0].member_id);
    return res.status(201).json({ ok: true, member_id: result.rows[0].member_id, status: 'pending', message: 'Registration submitted successfully. Your application is now pending administrator approval.' });
  } catch (err) {
    console.error('Registration failed:', err.message);
    return res.status(500).json({ error: 'Registration could not be saved. Please try again.' });
  }
});

// Public verification exposes only non-sensitive approved-member information.
app.get('/api/member/:id', requireDb, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT member_id,full_name,photo_url,status,rank,unit,year_of_entry,office_description FROM members WHERE member_id=$1 AND status='approved'`, [clean(req.params.id)]);
    if (!rows[0]) return res.status(404).json({ error: 'Approved member not found.' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Search failed.' }); }
});

app.post('/api/member/request-code', requireDb, async (req, res) => {
  try {
    const fullName = clean(req.body.full_name);
    const email = normalizeEmail(req.body.email);
    if (!fullName || !email) return res.status(400).json({ error: 'Full name and email are required.' });
    const { rows } = await pool.query(`SELECT * FROM members WHERE lower(email)=lower($1) AND lower(full_name)=lower($2) AND status='approved' LIMIT 1`, [email, fullName]);
    if (!rows[0]) return res.status(401).json({ error: 'Approved member account not found. Check your full name and email.' });
    await pool.query('UPDATE member_login_codes SET used_at=NOW() WHERE member_id=$1 AND used_at IS NULL', [rows[0].id]);
    const code = makeCode();
    await pool.query(`INSERT INTO member_login_codes(member_id,code_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '10 minutes')`, [rows[0].id, hashCode(code)]);
    await sendMemberCode(email, rows[0].full_name, code);
    res.json({ ok: true, message: 'A verification code has been sent to your email.' });
  } catch (err) {
    console.error('Member code request failed:', err.message);
    res.status(503).json({ error: err.message.includes('email service') ? err.message : 'Unable to send login code. Please try again.' });
  }
});

app.post('/api/member/verify-code', requireDb, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const fullName = clean(req.body.full_name);
    const code = clean(req.body.code);
    if (!email || !fullName || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit verification code.' });
    const member = await pool.query(`SELECT * FROM members WHERE lower(email)=lower($1) AND lower(full_name)=lower($2) AND status='approved' LIMIT 1`, [email, fullName]);
    if (!member.rows[0]) return res.status(401).json({ error: 'Member account not found.' });
    const m = member.rows[0];
    const q = await pool.query(`SELECT * FROM member_login_codes WHERE member_id=$1 AND used_at IS NULL AND expires_at>NOW() ORDER BY created_at DESC LIMIT 1`, [m.id]);
    if (!q.rows[0]) return res.status(401).json({ error: 'Code expired. Request a new code.' });
    const record = q.rows[0];
    if (record.attempts >= 5) return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
    if (hashCode(code) !== record.code_hash) {
      await pool.query('UPDATE member_login_codes SET attempts=attempts+1 WHERE id=$1', [record.id]);
      return res.status(401).json({ error: 'Incorrect verification code.' });
    }
    await pool.query('UPDATE member_login_codes SET used_at=NOW() WHERE id=$1', [record.id]);
    await pool.query('UPDATE members SET last_login_at=NOW() WHERE id=$1', [m.id]);
    req.session.member = { id: m.id, member_id: m.member_id, full_name: m.full_name };
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Login verification failed.' }); }
});

app.get('/api/member/me', requireMember, requireDb, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id,member_id,full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,year_of_entry,rank,office_description,photo_url,status,created_at,approved_at,last_login_at FROM members WHERE id=$1 AND status='approved'`, [req.session.member.id]);
    if (!rows[0]) return res.status(401).json({ error: 'Member account is no longer active.' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Unable to load member profile.' }); }
});
app.post('/api/member/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.post('/api/admin/login', requireDb, async (req, res) => {
  try {
    const username = clean(req.body.username);
    const password = String(req.body.password || '');
    const { rows } = await pool.query('SELECT * FROM admins WHERE username=$1 LIMIT 1', [username]);
    if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Invalid username or password.' });
    req.session.admin = { id: rows[0].id, username: rows[0].username, role: rows[0].role };
    res.json({ ok: true, admin: req.session.admin });
  } catch { res.status(500).json({ error: 'Admin login failed.' }); }
});
app.post('/api/admin/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/admin/me', requireAdmin, (req, res) => res.json(req.session.admin));

app.get('/api/admin/stats', requireAdmin, requireDb, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT COUNT(*)::int total, COUNT(*) FILTER(WHERE status='pending')::int pending, COUNT(*) FILTER(WHERE status='approved')::int approved, COUNT(*) FILTER(WHERE status='rejected')::int rejected, COUNT(*) FILTER(WHERE photo_url IS NOT NULL AND photo_url<>'')::int with_photo FROM members`);
    const units = await pool.query(`SELECT COALESCE(NULLIF(unit,''),'Unassigned') unit,COUNT(*)::int count FROM members GROUP BY 1 ORDER BY count DESC,unit`);
    res.json({ summary: rows[0], units: units.rows });
  } catch { res.status(500).json({ error: 'Unable to load statistics.' }); }
});

app.get('/api/admin/members', requireAdmin, requireDb, async (req, res) => {
  try {
    const status = clean(req.query.status || 'all');
    const q = clean(req.query.q);
    const params = [];
    const where = [];
    if (status !== 'all') { params.push(status); where.push(`status=$${params.length}`); }
    if (q) { params.push('%' + q + '%'); where.push(`(full_name ILIKE $${params.length} OR member_id ILIKE $${params.length} OR phone ILIKE $${params.length} OR email ILIKE $${params.length} OR unit ILIKE $${params.length} OR state ILIKE $${params.length} OR lga ILIKE $${params.length})`); }
    const sql = `SELECT * FROM members ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY created_at DESC`;
    const { rows } = await pool.query(sql, params);
    res.json(rows);
  } catch { res.status(500).json({ error: 'Unable to load members.' }); }
});

app.get('/api/admin/members/:id', requireAdmin, requireDb, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM members WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Member not found.' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Unable to load member.' }); }
});

app.patch('/api/admin/members/:id', requireAdmin, requireDb, async (req, res) => {
  try {
    const d = req.body || {};
    const allowed = ['approved', 'rejected', 'pending'];
    if (d.status && !allowed.includes(d.status)) return res.status(400).json({ error: 'Invalid status.' });
    const { rows } = await pool.query(`
      UPDATE members SET
        full_name=COALESCE($1,full_name), phone=COALESCE($2,phone), email=COALESCE($3,email),
        state=COALESCE($4,state), lga=COALESCE($5,lga), gender=COALESCE($6,gender), date_of_birth=COALESCE($7,date_of_birth),
        address=COALESCE($8,address), emergency_contact=COALESCE($9,emergency_contact), emergency_phone=COALESCE($10,emergency_phone),
        blood_group=COALESCE($11,blood_group), qualification=COALESCE($12,qualification), first_aid_level=COALESCE($13,first_aid_level),
        unit=COALESCE($14,unit), year_of_entry=COALESCE($15,year_of_entry), rank=COALESCE($16,rank), office_description=COALESCE($17,office_description),
        photo_url=COALESCE($18,photo_url), status=COALESCE($19,status),
        approved_at=CASE WHEN COALESCE($19,status)='approved' THEN COALESCE(approved_at,NOW()) WHEN COALESCE($19,status)='pending' THEN NULL ELSE approved_at END
      WHERE id=$20 RETURNING *`,
      [d.full_name, d.phone, d.email ? normalizeEmail(d.email) : d.email, d.state, d.lga, d.gender, d.date_of_birth || null, d.address, d.emergency_contact, d.emergency_phone, d.blood_group, d.qualification, d.first_aid_level, d.unit, d.year_of_entry, d.rank, d.office_description, d.photo_url, d.status, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Member not found.' });
    await audit(req, d.status === 'approved' ? 'approve_member' : d.status === 'rejected' ? 'reject_member' : 'update_member', rows[0].id, JSON.stringify({ fields: Object.keys(d) }));
    res.json(rows[0]);
  } catch (err) { console.error('Admin member update failed:', err.message); res.status(500).json({ error: 'Update failed.' }); }
});

app.delete('/api/admin/members/:id', requireAdmin, requireDb, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM members WHERE id=$1 RETURNING id,member_id', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Member not found.' });
    await audit(req, 'delete_member', null, JSON.stringify({ member_id: result.rows[0].member_id }));
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Delete failed.' }); }
});

app.post('/api/admin/members/:id/photo', requireAdmin, requireDb, async (req, res) => {
  try {
    const photo = String(req.body.photo_url || '');
    if (!photo.startsWith('data:image/')) return res.status(400).json({ error: 'A valid photo is required.' });
    if (photo.length > 1500000) return res.status(413).json({ error: 'Photo is too large.' });
    const { rows } = await pool.query('UPDATE members SET photo_url=$1 WHERE id=$2 RETURNING *', [photo, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Member not found.' });
    await audit(req, 'update_photo', rows[0].id);
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Photo update failed.' }); }
});

app.get('/api/admin/admins', requireAdmin, requireDb, async (req, res) => {
  try { const { rows } = await pool.query('SELECT id,username,role,created_at FROM admins ORDER BY created_at ASC'); res.json(rows); }
  catch { res.status(500).json({ error: 'Unable to load admin accounts.' }); }
});
app.post('/api/admin/admins', requireAdmin, requireDb, async (req, res) => {
  try {
    if (req.session.admin.role !== 'super_admin') return res.status(403).json({ error: 'Only a super administrator can add administrators.' });
    const username = clean(req.body.username);
    const password = String(req.body.password || '');
    const role = clean(req.body.role || 'approver');
    if (!username || password.length < 8) return res.status(400).json({ error: 'Username and a password of at least 8 characters are required.' });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query('INSERT INTO admins(username,password_hash,role) VALUES($1,$2,$3) RETURNING id,username,role,created_at', [username, hash, role]);
    await audit(req, 'create_admin', null, JSON.stringify({ username, role }));
    res.status(201).json(rows[0]);
  } catch (err) { res.status(409).json({ error: err.code === '23505' ? 'That administrator username already exists.' : 'Unable to create administrator.' }); }
});

app.get('/api/admin/audit-logs', requireAdmin, requireDb, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT a.id,a.action,a.details,a.created_at,ad.username,m.full_name,m.member_id FROM audit_logs a LEFT JOIN admins ad ON ad.id=a.admin_id LEFT JOIN members m ON m.id=a.member_id ORDER BY a.created_at DESC LIMIT 200`);
    res.json(rows);
  } catch { res.status(500).json({ error: 'Unable to load audit history.' }); }
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found.' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Fityanul Islam portal running on ${PORT}`));
