
import express from 'express';
import session from 'express-session';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import methodOverride from 'method-override';
import path from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false
}));

let db;
async function initDb() {
  db = await open({
    filename: path.join(__dirname, 'cadmdt.sqlite'),
    driver: sqlite3.Database
  });

  await db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('DISPATCH','OFFICER','FIREEMS','CIVILIAN','ADMIN'))
    );

    CREATE TABLE IF NOT EXISTS units (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      callsign TEXT UNIQUE NOT NULL,
      department TEXT NOT NULL CHECK (department IN ('LEO','FIRE','EMS','CIVILIAN')),
      user_id INTEGER UNIQUE,
      status TEXT NOT NULL DEFAULT '10-8',
      location TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS calls (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      caller_name TEXT,
      caller_phone TEXT,
      location TEXT,
      status TEXT NOT NULL DEFAULT 'OPEN',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS call_assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      call_id TEXT NOT NULL,
      unit_id INTEGER NOT NULL,
      FOREIGN KEY(call_id) REFERENCES calls(id) ON DELETE CASCADE,
      FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE,
      UNIQUE(call_id, unit_id)
    );

    CREATE TABLE IF NOT EXISTS bolos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL CHECK (type IN ('PERSON','VEHICLE')),
      details TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS plates (
      plate TEXT PRIMARY KEY,
      make TEXT, model TEXT, color TEXT,
      registered_to TEXT
    );

    CREATE TABLE IF NOT EXISTS civilians (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT NOT NULL,
      dob TEXT,
      address TEXT,
      notes TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author_user_id INTEGER,
      type TEXT NOT NULL CHECK (type IN ('CITATION','ARREST','INCIDENT')),
      subject_name TEXT,
      details TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
  `);

  // Seed one admin/dispatch/officer/civilian if none exist
  const row = await db.get('SELECT COUNT(*) as c FROM users');
  if (row.c === 0) {
    const users = [
      {username:'admin', password:'admin123', role:'ADMIN'},
      {username:'dispatch', password:'dispatch123', role:'DISPATCH'},
      {username:'officer1', password:'officer123', role:'OFFICER'},
      {username:'fire1', password:'fire123', role:'FIREEMS'},
      {username:'civ1', password:'civ123', role:'CIVILIAN'}
    ];
    for (const u of users) {
      const hash = await bcrypt.hash(u.password, 10);
      await db.run('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)', [u.username, hash, u.role]);
    }
    await db.run("INSERT OR IGNORE INTO units (callsign, department, user_id, status) VALUES ('1-A-01','LEO',(SELECT id FROM users WHERE username='officer1'),'10-8')");
    await db.run("INSERT OR IGNORE INTO units (callsign, department, user_id, status) VALUES ('F-1','FIRE',(SELECT id FROM users WHERE username='fire1'),'AVAILABLE')");
    await db.run("INSERT OR IGNORE INTO civilians (user_id, name, dob, address) VALUES ((SELECT id FROM users WHERE username='civ1'),'John Doe','1999-01-01','123 Main St')");
    await db.run("INSERT OR IGNORE INTO plates (plate, make, model, color, registered_to) VALUES ('ABC123','Vapid','Dominator','Black','John Doe')");
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.session.user || !roles.includes(req.session.user.role)) return res.status(403).send('Forbidden');
    next();
  };
}

// Auth
app.get('/login', (req,res)=>{
  res.render('login', { error: null });
});
app.post('/login', async (req,res)=>{
  const {username, password} = req.body;
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) return res.render('login', { error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.render('login', { error: 'Invalid credentials' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect('/dashboard');
});
app.post('/register', async (req,res)=>{
  const {username, password, role} = req.body;
  if (!username || !password || !role) return res.status(400).send('Missing fields');
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.run('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)', [username, hash, role]);
    res.redirect('/login');
  } catch (e) {
    res.status(400).send('User exists or invalid');
  }
});
app.post('/logout', (req,res)=>{
  req.session.destroy(()=> res.redirect('/login'));
});

// Dashboard
app.get('/', (req,res)=> res.redirect('/dashboard'));
app.get('/dashboard', requireAuth, async (req,res)=>{
  const user = req.session.user;
  const calls = await db.all('SELECT * FROM calls ORDER BY created_at DESC LIMIT 25');
  const bolos = await db.all('SELECT * FROM bolos ORDER BY created_at DESC LIMIT 25');
  const units = await db.all('SELECT * FROM units ORDER BY callsign ASC');
  res.render('dashboard', { user, calls, bolos, units });
});

// Dispatch views
app.get('/dispatch', requireAuth, requireRoles('DISPATCH','ADMIN'), async (req,res)=>{
  const calls = await db.all('SELECT * FROM calls ORDER BY created_at DESC');
  const units = await db.all('SELECT * FROM units ORDER BY callsign ASC');
  res.render('dispatch', { user: req.session.user, calls, units });
});

// Create 911 call
app.post('/calls', requireAuth, async (req,res)=>{
  const { type, description, caller_name, caller_phone, location } = req.body;
  const id = uuidv4().slice(0,8).toUpperCase();
  await db.run('INSERT INTO calls (id,type,description,caller_name,caller_phone,location,status) VALUES (?,?,?,?,?,?,?)',
    [id, type, description, caller_name, caller_phone, location, 'OPEN']);
  res.redirect('back');
});

// Update call status
app.post('/calls/:id/status', requireAuth, async (req,res)=>{
  await db.run('UPDATE calls SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
  res.redirect('back');
});

// Assign unit to call
app.post('/calls/:id/assign', requireAuth, requireRoles('DISPATCH','ADMIN'), async (req,res)=>{
  const { unit_id } = req.body;
  try {
    await db.run('INSERT OR IGNORE INTO call_assignments (call_id, unit_id) VALUES (?,?)', [req.params.id, unit_id]);
  } catch {}
  res.redirect('back');
});

// Unit status
app.post('/units/:id/status', requireAuth, async (req,res)=>{
  await db.run('UPDATE units SET status = ?, location = ? WHERE id = ?', [req.body.status, req.body.location || null, req.params.id]);
  res.redirect('back');
});

// BOLOs
app.post('/bolos', requireAuth, async (req,res)=>{
  await db.run('INSERT INTO bolos (type, details) VALUES (?,?)', [req.body.type, req.body.details]);
  res.redirect('back');
});
app.post('/bolos/:id/delete', requireAuth, async (req,res)=>{
  await db.run('DELETE FROM bolos WHERE id = ?', [req.params.id]);
  res.redirect('back');
});

// Lookups
app.get('/lookup/plate', requireAuth, async (req,res)=>{
  const plate = (req.query.plate || '').toUpperCase().trim();
  const row = await db.get('SELECT * FROM plates WHERE plate = ?', [plate]);
  res.json(row || {});
});
app.get('/lookup/person', requireAuth, async (req,res)=>{
  const name = (req.query.name || '').trim();
  const civ = await db.get('SELECT * FROM civilians WHERE name LIKE ? LIMIT 1', [`%${name}%`]);
  res.json(civ || {});
});

// Civilian: manage characters
app.get('/civ', requireAuth, requireRoles('CIVILIAN','ADMIN'), async (req,res)=>{
  const chars = await db.all('SELECT * FROM civilians WHERE user_id = ?', [req.session.user.id]);
  res.render('civ', { user: req.session.user, chars });
});
app.post('/civ', requireAuth, requireRoles('CIVILIAN','ADMIN'), async (req,res)=>{
  const { name, dob, address, notes } = req.body;
  await db.run('INSERT INTO civilians (user_id, name, dob, address, notes) VALUES (?,?,?,?,?)',
    [req.session.user.id, name, dob, address, notes]);
  res.redirect('/civ');
});

// Officer: simple reports
app.get('/reports/new', requireAuth, requireRoles('OFFICER','FIREEMS','ADMIN'), (req,res)=>{
  res.render('report_new', { user: req.session.user });
});
app.post('/reports', requireAuth, requireRoles('OFFICER','FIREEMS','ADMIN'), async (req,res)=>{
  const { type, subject_name, details } = req.body;
  await db.run('INSERT INTO reports (author_user_id,type,subject_name,details) VALUES (?,?,?,?)',
    [req.session.user.id, type, subject_name, details]);
  res.redirect('/dashboard');
});

// Quick API for units list (AJAX polling)
app.get('/api/units', requireAuth, async (req,res)=>{
  const units = await db.all('SELECT * FROM units ORDER BY callsign ASC');
  res.json(units);
});
app.get('/api/calls', requireAuth, async (req,res)=>{
  const calls = await db.all('SELECT * FROM calls ORDER BY created_at DESC LIMIT 50');
  res.json(calls);
});

app.listen(PORT, async () => {
  await initDb();
  console.log(`CAD/MDT running on http://localhost:${PORT}`);
});
