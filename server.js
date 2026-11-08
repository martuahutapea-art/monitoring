const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const isProduction = process.env.NODE_ENV === 'production';

if (!DATABASE_URL) {
  console.error('DATABASE_URL belum diatur. Tambahkan connection string Neon sebagai environment variable.');
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET wajib diisi dengan nilai acak minimal 32 karakter.');
  process.exit(1);
}

if (isProduction) app.set('trust proxy', 1);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
pool.on('error', (err) => console.error('Kesalahan koneksi database:', err.message));

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(80) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('admin','student','teacher','industry')),
      full_name VARCHAR(160) NOT NULL,
      nis VARCHAR(40) UNIQUE,
      class_name VARCHAR(100),
      major VARCHAR(150),
      company VARCHAR(180),
      supervisor VARCHAR(160),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS attendance (
      id BIGSERIAL PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES users(id),
      attendance_date DATE NOT NULL,
      check_in TIMESTAMPTZ,
      check_out TIMESTAMPTZ,
      status VARCHAR(20) NOT NULL CHECK(status IN ('hadir','izin','sakit','alpha')),
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(student_id, attendance_date)
    );
    CREATE TABLE IF NOT EXISTS journals (
      id BIGSERIAL PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES users(id),
      journal_date DATE NOT NULL,
      activity TEXT NOT NULL,
      learning TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'menunggu' CHECK(status IN ('menunggu','disetujui','revisi')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_id BIGINT REFERENCES users(id),
      action VARCHAR(100) NOT NULL,
      target_type VARCHAR(80),
      target_id BIGINT,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_attendance_student_date ON attendance(student_id, attendance_date DESC);
    CREATE INDEX IF NOT EXISTS idx_journals_student_date ON journals(student_id, journal_date DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
  `);

  // Demo accounts are created only when explicitly enabled. Never enable this on a public production deployment.
  if (process.env.SEED_DEMO === 'true' && !isProduction) {
    const demoUsers = [
      ['admin', process.env.DEMO_ADMIN_PASSWORD || 'Admin123!', 'admin', 'Administrator SIMON', null, null, null, null, null],
      ['siswa', process.env.DEMO_STUDENT_PASSWORD || 'Siswa123!', 'student', 'Siswa Demo', '2026001', 'XI TKJ', 'Teknik Komputer Jaringan', 'Perusahaan Contoh', 'Guru Demo'],
      ['guru', process.env.DEMO_TEACHER_PASSWORD || 'Guru123!', 'teacher', 'Guru Pembimbing', null, null, null, null, null],
      ['industri', process.env.DEMO_INDUSTRY_PASSWORD || 'Industri123!', 'industry', 'Pembimbing Industri', null, null, null, null, null]
    ];
    for (const u of demoUsers) {
      const hash = await bcrypt.hash(u[1], 12);
      await pool.query(`INSERT INTO users(username,password_hash,role,full_name,nis,class_name,major,company,supervisor)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(username) DO NOTHING`, [u[0], hash, ...u.slice(2)]);
    }
  }

  // Optional first administrator provisioning for a new hosted database.
  // Set these variables in the hosting dashboard, deploy once, then remove the password variable.
  const bootstrapUsername = process.env.BOOTSTRAP_ADMIN_USERNAME;
  const bootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  const bootstrapName = process.env.BOOTSTRAP_ADMIN_NAME || 'Administrator SIMON';
  if (bootstrapUsername && bootstrapPassword) {
    if (bootstrapPassword.length < 14) throw new Error('BOOTSTRAP_ADMIN_PASSWORD harus minimal 14 karakter.');
    const exists = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
    if (exists.rowCount === 0) {
      const hash = await bcrypt.hash(bootstrapPassword, 12);
      await pool.query("INSERT INTO users(username,password_hash,role,full_name) VALUES($1,$2,'admin',$3) ON CONFLICT(username) DO NOTHING", [bootstrapUsername.trim(), hash, bootstrapName]);
      console.log('Akun administrator awal berhasil disiapkan.');
    }
  }
}

function jakartaDate() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
}
function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role, full_name: user.full_name,
    nis: user.nis, class_name: user.class_name, major: user.major, company: user.company, supervisor: user.supervisor };
}
function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
  next();
}
function roles(...allowed) {
  return (req, res, next) => {
    if (!req.session.user || !allowed.includes(req.session.user.role)) return res.status(403).json({ error: 'Anda tidak memiliki akses.' });
    next();
  };
}
async function audit(actorId, action, targetType, targetId, details = '') {
  await pool.query('INSERT INTO audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)',
    [actorId || null, action, targetType || null, targetId || null, details]);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'simon.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProduction, maxAge: 8 *  60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: 'draft-7', legacyHeaders: false }));

app.post('/api/login', rateLimit({ windowMs: 10 * 60 * 1000, limit: 8, message: { error: 'Terlalu banyak percobaan login. Coba lagi nanti.' } }), async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || username.length > 80 || password.length > 200) return res.status(400).json({ error: 'Username atau password tidak valid.' });
    const result = await pool.query('SELECT * FROM users WHERE username=$1', [username.trim()]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      await audit(null, 'login_gagal', 'user', null, `username=${username.trim().slice(0, 80)}`);
      return res.status(401).json({ error: 'Username atau password salah.' });
    }
    req.session.regenerate(async (err) => {
      if (err) return res.status(500).json({ error: 'Gagal membuat sesi.' });
      req.session.user = publicUser(user);
      try { await audit(user.id, 'login', 'user', user.id); res.json({ user: req.session.user }); }
      catch (e) { next(e); }
    });
  } catch (e) { next(e); }
});
app.post('/api/logout', auth, async (req, res, next) => {
  try { await audit(req.session.user.id, 'logout', 'user', req.session.user.id); req.session.destroy(() => res.json({ ok: true })); }
  catch (e) { next(e); }
});
app.get('/api/me', auth, (req, res) => res.json({ user: req.session.user }));

app.get('/api/dashboard', auth, async (req, res, next) => {
  try {
    const user = req.session.user;
    const attendance = user.role === 'student'
      ? await pool.query('SELECT status, COUNT(*)::int AS total FROM attendance WHERE student_id=$1 GROUP BY status', [user.id])
      : await pool.query('SELECT status, COUNT(*)::int AS total FROM attendance GROUP BY status');
    const journals = user.role === 'student'
      ? await pool.query('SELECT COUNT(*)::int AS total FROM journals WHERE student_id=$1', [user.id])
      : await pool.query('SELECT COUNT(*)::int AS total FROM journals');
    const students = user.role === 'admin' || user.role === 'teacher' || user.role === 'industry'
      ? await pool.query("SELECT COUNT(*)::int AS total FROM users WHERE role='student'") : { rows: [{ total: 1 }] };
    res.json({ attendance: attendance.rows, journals: journals.rows[0].total, students: students.rows[0].total });
  } catch (e) { next(e); }
});
app.get('/api/profile', auth, async (req, res, next) => {
  try {
    const user = req.session.user;
    if (user.role === 'student') return res.json({ profile: user });
    const id = Number(req.query.id);
    if (!id || !['admin', 'teacher', 'industry'].includes(user.role)) return res.json({ profile: user });
    const result = await pool.query("SELECT id,username,role,full_name,nis,class_name,major,company,supervisor FROM users WHERE id=$1 AND role='student'", [id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Profil siswa tidak ditemukan.' });
    res.json({ profile: result.rows[0] });
  } catch (e) { next(e); }
});
app.get('/api/students', auth, roles('admin', 'teacher', 'industry'), async (req, res, next) => {
  try { const r = await pool.query("SELECT id,full_name,nis,class_name,major,company,supervisor FROM users WHERE role='student' ORDER BY full_name"); res.json({ students: r.rows }); }
  catch (e) { next(e); }
});
app.get('/api/attendance', auth, async (req, res, next) => {
  try {
    const user = req.session.user;
    const r = user.role === 'student'
      ? await pool.query('SELECT a.*,u.full_name FROM attendance a JOIN users u ON u.id=a.student_id WHERE a.student_id=$1 ORDER BY attendance_date DESC', [user.id])
      : await pool.query('SELECT a.*,u.full_name FROM attendance a JOIN users u ON u.id=a.student_id ORDER BY attendance_date DESC LIMIT 200');
    res.json({ attendance: r.rows });
  } catch (e) { next(e); }
});
app.post('/api/attendance/checkin', auth, roles('student'), async (req, res, next) => {
  try {
    const { latitude, longitude } = req.body || {};
    const lat = Number(latitude), lon = Number(longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return res.status(400).json({ error: 'Lokasi GPS tidak valid. Izinkan akses lokasi.' });
    // DEMO coordinates only. Replace with approved company coordinates and radius before real deployment.
    const companyLat = Number(process.env.COMPANY_LAT || -0.9471);
    const companyLon = Number(process.env.COMPANY_LON || 100.4172);
    const radiusMeters = Number(process.env.GEOFENCE_RADIUS_METERS || 1000);
    const rad = d => d * Math.PI / 180;
    const dLat = rad(lat - companyLat), dLon = rad(lon - companyLon);
    const a = Math.sin(dLat / 2) ** 2 + Math.cos(rad(companyLat)) * Math.cos(rad(lat)) * Math.sin(dLon / 2) ** 2;
    const distance = 6371000 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    if (distance > radiusMeters) return res.status(403).json({ error: `Di luar radius lokasi (${Math.round(distance)} meter). Periksa lokasi perusahaan.` });
    const r = await pool.query("INSERT INTO attendance(student_id,attendance_date,check_in,status,latitude,longitude) VALUES($1,$2,NOW(),'hadir',$3,$4) ON CONFLICT(student_id,attendance_date) DO NOTHING RETURNING id", [req.session.user.id, jakartaDate(), lat, lon]);
    if (!r.rows[0]) return res.status(409).json({ error: 'Absensi hari ini sudah tercatat.' });
    await audit(req.session.user.id, 'checkin', 'attendance', r.rows[0].id, `distance=${Math.round(distance)}m`);
    res.json({ ok: true, message: 'Check-in berhasil dicatat oleh server.' });
  } catch (e) { next(e); }
});
app.post('/api/attendance/checkout', auth, roles('student'), async (req, res, next) => {
  try {
    const r = await pool.query('UPDATE attendance SET check_out=NOW() WHERE student_id=$1 AND attendance_date=$2 AND check_out IS NULL RETURNING id', [req.session.user.id, jakartaDate()]);
    if (!r.rows[0]) return res.status(400).json({ error: 'Check-in belum dilakukan atau check-out sudah tercatat.' });
    await audit(req.session.user.id, 'checkout', 'attendance', r.rows[0].id);
    res.json({ ok: true, message: 'Check-out berhasil.' });
  } catch (e) { next(e); }
});
app.get('/api/journals', auth, async (req, res, next) => {
  try {
    const user = req.session.user;
    const r = user.role === 'student'
      ? await pool.query('SELECT j.*,u.full_name FROM journals j JOIN users u ON u.id=j.student_id WHERE j.student_id=$1 ORDER BY journal_date DESC', [user.id])
      : await pool.query('SELECT j.*,u.full_name FROM journals j JOIN users u ON u.id=j.student_id ORDER BY journal_date DESC LIMIT 200');
    res.json({ journals: r.rows });
  } catch (e) { next(e); }
});
app.post('/api/journals', auth, roles('student'), async (req, res, next) => {
  try {
    const { activity, learning } = req.body || {};
    if (typeof activity !== 'string' || activity.trim().length < 5 || activity.length > 2000) return res.status(400).json({ error: 'Kegiatan minimal 5 karakter dan maksimal 2.000 karakter.' });
    if (typeof learning !== 'string' || learning.length > 2000) return res.status(400).json({ error: 'Kolom pembelajaran tidak valid.' });
    const r = await pool.query("INSERT INTO journals(student_id,journal_date,activity,learning) VALUES($1,$2,$3,$4) RETURNING id", [req.session.user.id, jakartaDate(), activity.trim(), learning.trim()]);
    await audit(req.session.user.id, 'journal_submit', 'journal', r.rows[0].id);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.patch('/api/journals/:id/status', auth, roles('admin', 'teacher', 'industry'), async (req, res, next) => {
  try {
    const { status } = req.body || {};
    if (!['disetujui', 'revisi'].includes(status)) return res.status(400).json({ error: 'Status tidak valid.' });
    const id = Number(req.params.id);
    const r = await pool.query('UPDATE journals SET status=$1 WHERE id=$2 RETURNING id', [status, id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Jurnal tidak ditemukan.' });
    await audit(req.session.user.id, 'journal_review', 'journal', id, status);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.get('/api/audit', auth, roles('admin'), async (req, res, next) => {
  try { const r = await pool.query('SELECT l.*,u.full_name AS actor_name FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.id DESC LIMIT 100'); res.json({ logs: r.rows }); }
  catch (e) { next(e); }
});
app.get('/api/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, service: 'SIMON PRAKERIN', database: 'connected' }); }
  catch (_) { res.status(503).json({ ok: false, database: 'disconnected' }); }
});
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Terjadi kesalahan server.' }); });

initDatabase().then(() => {
  app.listen(PORT, () => console.log(`SIMON PRAKERIN berjalan pada port ${PORT}`));
}).catch(err => {
  console.error('Gagal menyiapkan database:', err.message);
  process.exit(1);
});
