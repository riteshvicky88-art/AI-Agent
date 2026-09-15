// =====================================================================
// NucleoSense — server.js
// 21 CFR Part 11 Compliant — Medical Device Manufacturing
//
// Compliance features:
//  1. Electronic Signatures — re-auth on every critical change
//  2. Tamper-evident Audit Trail — append-only, never delete
//  3. Role-based Access Control — unique user IDs
//  4. Password Policy — complexity, expiry (90 days), history (5), lockout (3 attempts)
//  5. Session Timeout — configurable inactivity timeout
//  6. Reason for Change — mandatory on every setpoint change
//  7. Record Integrity — audit records cannot be modified or deleted
//  8. System events — boot, shutdown, errors all logged
//
// Install: npm install express sql.js bcryptjs jsonwebtoken cors
// Run:     node server.js
// =====================================================================

const express   = require('express');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const fs        = require('fs');
const path      = require('path');
const initSqlJs = require('sql.js');

const app        = express();
const PORT       = 3000;
const JWT_SECRET = 'nucleo-sense-21cfr-jwt-secret-2024-change-in-prod';
const DB_FILE    = path.join(__dirname, 'nucleosense.db');

// ── 21 CFR Part 11 Policy Constants ──────────────────────────────────
const CFR = {
  SESSION_TIMEOUT_MS:    30 * 60 * 1000,   // 30 min inactivity timeout
  MAX_LOGIN_ATTEMPTS:    3,                  // lockout after 3 failures
  LOCKOUT_DURATION_MS:   30 * 60 * 1000,   // 30 min lockout
  PASSWORD_MIN_LENGTH:   8,
  PASSWORD_REQUIRE_UPPER:true,
  PASSWORD_REQUIRE_LOWER:true,
  PASSWORD_REQUIRE_DIGIT:true,
  PASSWORD_REQUIRE_SPEC: true,
  PASSWORD_HISTORY:      5,                  // cannot reuse last 5 passwords
  PASSWORD_EXPIRY_DAYS:  90,                 // passwords expire after 90 days
  REQUIRE_REASON:        true,               // mandatory reason for setpoint changes
  REQUIRE_ESIG:          true,               // require e-signature (re-auth) for changes
  SYSTEM_NAME:          'NucleoSense',
  SYSTEM_VERSION:       '1.0.0',
  REGULATION:           '21 CFR Part 11',
};

// ── UUID v4 generator (21 CFR §11.10e — unique ID for every audit entry) ──
function uuidv4() {
  return crypto.randomUUID ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = crypto.randomBytes(1)[0] % 16;
        return (c==='x'?r:(r&0x3|0x8)).toString(16);
      });
}

// ── NTP-style timestamp (item 8) — always UTC ISO with ms precision ──
function ntpNow() {
  return new Date().toISOString(); // UTC — use NTP daemon on host for accuracy
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── DB globals ────────────────────────────────────────────────────────
let db;
let dbDirty = false;

// ── Init DB ───────────────────────────────────────────────────────────
async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_FILE)) {
    try {
      db = new SQL.Database(fs.readFileSync(DB_FILE));
      console.log(`[DB] Loaded: ${DB_FILE} (${(fs.statSync(DB_FILE).size/1024).toFixed(1)} KB)`);
    } catch(e) {
      console.error('[DB] Corrupt, creating fresh:', e.message);
      db = new SQL.Database();
    }
  } else {
    db = new SQL.Database();
    console.log('[DB] New database created');
  }
  createSchema();
  seedDefaults();
  setInterval(() => { if (dbDirty) saveDB(); }, 3000);
  setInterval(pruneReadings, 60000);
  saveDB();
  // Log system start
  cfr_audit('SYSTEM','System','system','system_start','system','server',
    `${CFR.SYSTEM_NAME} v${CFR.SYSTEM_VERSION} started — ${CFR.REGULATION} mode`,'','','127.0.0.1');
}

// ── Schema ────────────────────────────────────────────────────────────
function createSchema() {
  db.run(`
    -- ── USERS (21 CFR: unique user ID, role, password history) ──────────
    CREATE TABLE IF NOT EXISTS users (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      username            TEXT UNIQUE NOT NULL,
      password            TEXT NOT NULL,
      full_name           TEXT NOT NULL DEFAULT '',
      email               TEXT DEFAULT '',
      role                TEXT NOT NULL DEFAULT 'operator',
      enabled             INTEGER NOT NULL DEFAULT 1,
      is_protected        INTEGER NOT NULL DEFAULT 0,
      failed_attempts     INTEGER NOT NULL DEFAULT 0,
      locked_until        TEXT DEFAULT NULL,
      password_changed_at TEXT DEFAULT (datetime('now')),
      must_change_pw      INTEGER NOT NULL DEFAULT 0,
      created_at          TEXT DEFAULT (datetime('now')),
      created_by          TEXT DEFAULT 'SYSTEM',
      updated_at          TEXT DEFAULT (datetime('now'))
    );

    -- ── PASSWORD HISTORY (21 CFR: cannot reuse last N passwords) ─────────
    CREATE TABLE IF NOT EXISTS password_history (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      password   TEXT NOT NULL,
      changed_at TEXT DEFAULT (datetime('now'))
    );

    -- ── DEVICES ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS devices (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      type        TEXT NOT NULL DEFAULT 'generic',
      ip          TEXT DEFAULT '',
      description TEXT DEFAULT '',
      enabled     INTEGER NOT NULL DEFAULT 1,
      created_at  TEXT DEFAULT (datetime('now')),
      created_by  TEXT DEFAULT 'SYSTEM',
      last_seen   TEXT
    );

    -- ── SETPOINTS (21 CFR: full history, never overwrite) ────────────────
    -- Every SET is a new row — complete history preserved
    CREATE TABLE IF NOT EXISTS device_setpoints (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id    TEXT NOT NULL,
      param_id     TEXT NOT NULL,
      param_label  TEXT NOT NULL,
      unit         TEXT DEFAULT '',
      set_value    REAL NOT NULL,
      set_by       TEXT NOT NULL,
      set_by_name  TEXT DEFAULT '',
      set_at       TEXT DEFAULT (datetime('now')),
      reason       TEXT NOT NULL DEFAULT '',
      esig_verified INTEGER NOT NULL DEFAULT 0,
      is_current   INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (device_id) REFERENCES devices(id)
    );
    CREATE INDEX IF NOT EXISTS idx_sp_device ON device_setpoints(device_id, param_id, is_current);

    -- ── PROFILES (Recipe Programming) — multi-device setpoint bundles ────
    -- A profile is a named, reusable set of setpoints across one or more
    -- devices. "Starting" a profile writes every item as a real setpoint
    -- change (same code path as a manual change), so it inherits the same
    -- 21 CFR e-signature + reason + audit-trail guarantees.
    CREATE TABLE IF NOT EXISTS profiles (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      guid             TEXT NOT NULL,
      name             TEXT NOT NULL,
      description      TEXT DEFAULT '',
      created_by       TEXT NOT NULL,
      created_by_name  TEXT DEFAULT '',
      created_at       TEXT DEFAULT (datetime('now')),
      updated_at       TEXT DEFAULT (datetime('now')),
      deleted          INTEGER NOT NULL DEFAULT 0,
      deleted_by       TEXT DEFAULT '',
      deleted_at       TEXT DEFAULT '',
      delete_reason    TEXT DEFAULT '',
      is_active        INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS profile_items (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      profile_id   INTEGER NOT NULL,
      device_id    TEXT NOT NULL,
      param_id     TEXT NOT NULL,
      param_label  TEXT DEFAULT '',
      unit         TEXT DEFAULT '',
      value        REAL NOT NULL,
      sort_order   INTEGER DEFAULT 0,
      FOREIGN KEY (profile_id) REFERENCES profiles(id)
    );
    CREATE INDEX IF NOT EXISTS idx_profile_items ON profile_items(profile_id);
    CREATE TABLE IF NOT EXISTS profile_runs (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      guid           TEXT NOT NULL,
      profile_id     INTEGER NOT NULL,
      profile_name   TEXT NOT NULL,
      run_by         TEXT NOT NULL,
      run_by_name    TEXT DEFAULT '',
      run_at         TEXT DEFAULT (datetime('now')),
      reason         TEXT NOT NULL,
      item_count     INTEGER DEFAULT 0,
      applied_count  INTEGER DEFAULT 0,
      failed_count   INTEGER DEFAULT 0,
      ip_address     TEXT DEFAULT '',
      details        TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_profile_runs ON profile_runs(profile_id);

    -- ── SENSOR READINGS ───────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS device_readings (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id  TEXT NOT NULL,
      timestamp  TEXT DEFAULT (datetime('now')),
      payload    TEXT NOT NULL,
      source_ip  TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_readings_dev ON device_readings(device_id, timestamp DESC);

    -- ── ALERTS ───────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS incidents (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      guid          TEXT NOT NULL,
      title         TEXT NOT NULL,
      description   TEXT NOT NULL,
      severity      TEXT NOT NULL,
      device_id     TEXT DEFAULT '',
      audit_ref     TEXT DEFAULT '',
      assigned_to   TEXT DEFAULT '',
      due_date      TEXT DEFAULT '',
      reported_by   TEXT NOT NULL,
      resolution    TEXT DEFAULT '',
      closed_by     TEXT DEFAULT '',
      closed_at     TEXT DEFAULT '',
      status        TEXT DEFAULT 'OPEN',
      created_at    TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alarm_escalation (
      id                 INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id          TEXT NOT NULL,
      param_id           TEXT DEFAULT '*',
      primary_contact    TEXT NOT NULL,
      secondary_contact  TEXT DEFAULT '',
      escalation_minutes INTEGER DEFAULT 15,
      created_by         TEXT NOT NULL,
      created_at         TEXT NOT NULL,
      UNIQUE(device_id, param_id)
    );
    CREATE TABLE IF NOT EXISTS firmware_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      guid           TEXT NOT NULL,
      device_id      TEXT NOT NULL,
      device_serial  TEXT DEFAULT '',
      old_version    TEXT DEFAULT '',
      new_version    TEXT NOT NULL,
      method         TEXT DEFAULT 'manual',
      applied_by     TEXT NOT NULL,
      applied_at     TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS data_logger (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      guid          TEXT NOT NULL,
      name          TEXT NOT NULL,
      device_id     TEXT NOT NULL,
      param_ids     TEXT DEFAULT '',
      interval_sec  INTEGER DEFAULT 5,
      status        TEXT DEFAULT 'RUNNING',
      started_by    TEXT NOT NULL,
      started_at    TEXT NOT NULL,
      stopped_by    TEXT DEFAULT '',
      stopped_at    TEXT DEFAULT '',
      notes         TEXT DEFAULT '',
      deleted        INTEGER DEFAULT 0,
      deleted_by     TEXT DEFAULT '',
      deleted_at     TEXT DEFAULT '',
      delete_reason  TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS data_logger_points (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      logger_id     INTEGER NOT NULL,
      timestamp     TEXT DEFAULT (datetime('now')),
      payload       TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id    TEXT,
      timestamp    TEXT DEFAULT (datetime('now')),
      type         TEXT NOT NULL,
      message      TEXT NOT NULL,
      value        REAL,
      threshold    REAL,
      acknowledged INTEGER NOT NULL DEFAULT 0,
      ack_by       TEXT,
      ack_at       TEXT,
      ack_reason   TEXT
    );

    -- ── 21 CFR AUDIT LOG (tamper-evident, append-only, never delete) ──────
    CREATE TABLE IF NOT EXISTS audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      guid          TEXT DEFAULT '',
      timestamp     TEXT DEFAULT (datetime('now')),
      username      TEXT NOT NULL,
      full_name     TEXT DEFAULT '',
      role          TEXT DEFAULT '',
      action        TEXT NOT NULL,
      target_type   TEXT DEFAULT '',
      target_id     TEXT DEFAULT '',
      description   TEXT DEFAULT '',
      old_value     TEXT DEFAULT '',
      new_value     TEXT DEFAULT '',
      reason        TEXT DEFAULT '',
      esig_username TEXT DEFAULT '',
      esig_verified INTEGER DEFAULT 0,
      ip_address    TEXT DEFAULT '',
      status        TEXT DEFAULT 'success',
      checksum      TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_audit_user   ON audit_log(username);
    CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

    -- ── SESSIONS ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS sessions (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      username    TEXT NOT NULL,
      token       TEXT NOT NULL,
      ip          TEXT DEFAULT '',
      created_at  TEXT DEFAULT (datetime('now')),
      expires_at  TEXT DEFAULT '',
      last_active TEXT DEFAULT (datetime('now'))
    );
  `);
  console.log('[DB] 21 CFR Part 11 schema ready');
}

// ── Seed defaults ─────────────────────────────────────────────────────
function seedDefaults() {
  // ── ALWAYS run per-user guards so new accounts are backfilled into
  //    existing databases automatically on next server restart. ──

  // ── 1. FACTORY — default primary account, seeded first (id=1),
  //       no forced password change, CANNOT be deleted by anyone.
  if (!queryOne('SELECT id FROM users WHERE username=?', ['factory'])) {
    const factPw = bcrypt.hashSync('Factory@789', 10);
    run(`INSERT INTO users (username,password,full_name,email,role,must_change_pw,created_by,is_protected)
         VALUES (?,?,?,?,?,0,?,1)`,
      ['factory', factPw, 'Factory Account', 'factory@facility.local', 'factory', 'SYSTEM']);
    const factUser = queryOne('SELECT id FROM users WHERE username=?', ['factory']);
    run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [factUser.id, factPw]);
    cfr_audit('SYSTEM','System','system','db_seed','users','factory','Factory default account created','','','127.0.0.1');
    console.log('[DB] Default user: factory / Factory@789  (factory role — protected, cannot be deleted)');
  } else {
    // Ensure existing factory row is always marked protected
    run(`UPDATE users SET is_protected=1 WHERE username='factory'`);
  }

  // ── 2. ADMIN
  if (!queryOne('SELECT id FROM users WHERE username=?', ['admin'])) {
    const adminPw = bcrypt.hashSync('Admin@123', 10);
    run(`INSERT INTO users (username,password,full_name,email,role,created_by) VALUES (?,?,?,?,?,?)`,
      ['admin', adminPw, 'System Administrator', 'admin@facility.local', 'administrator', 'SYSTEM']);
    const adminUser = queryOne('SELECT id FROM users WHERE username=?', ['admin']);
    run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [adminUser.id, adminPw]);
    console.log('[DB] Default user: admin / Admin@123  (administrator role)');
  }

  // ── 3. OPERATOR
  if (!queryOne('SELECT id FROM users WHERE username=?', ['operator'])) {
    const opPw = bcrypt.hashSync('Oper@456', 10);
    run(`INSERT INTO users (username,password,full_name,email,role,created_by) VALUES (?,?,?,?,?,?)`,
      ['operator', opPw, 'Process Operator', 'operator@facility.local', 'operator', 'SYSTEM']);
    const opUser = queryOne('SELECT id FROM users WHERE username=?', ['operator']);
    run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [opUser.id, opPw]);
    console.log('[DB] Default user: operator / Oper@456  (operator role)');
  }

  // ── 4. QA OFFICER
  if (!queryOne('SELECT id FROM users WHERE username=?', ['qa_officer'])) {
    const qaePw = bcrypt.hashSync('QA@user789', 10);
    run(`INSERT INTO users (username,password,full_name,email,role,created_by) VALUES (?,?,?,?,?,?)`,
      ['qa_officer', qaePw, 'QA Officer', 'qa@facility.local', 'qa', 'SYSTEM']);
    const qaUser = queryOne('SELECT id FROM users WHERE username=?', ['qa_officer']);
    run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [qaUser.id, qaePw]);
    console.log('[DB] Default user: qa_officer / QA@user789  (qa role)');
  }

  // ── 5. SUPERVISOR
  if (!queryOne('SELECT id FROM users WHERE username=?', ['supervisor'])) {
    const supPw = bcrypt.hashSync('Super@321', 10);
    run(`INSERT INTO users (username,password,full_name,email,role,must_change_pw,created_by) VALUES (?,?,?,?,?,1,?)`,
      ['supervisor', supPw, 'Production Supervisor', 'supervisor@facility.local', 'supervisor', 'SYSTEM']);
    const supUser = queryOne('SELECT id FROM users WHERE username=?', ['supervisor']);
    run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [supUser.id, supPw]);
    console.log('[DB] Default user: supervisor / Super@321  (supervisor — must change pw on first login)');
  }

  saveDB();

  if (queryAll('SELECT id FROM devices').length === 0) {
    const devs = [
      { id:'pt100_01', name:'PT100 Temperature Sensor', type:'temp',   ip:'192.168.1.101', description:'Wheatstone bridge + InAmp on PA0' },
      { id:'vac_01',   name:'Vacuum Pressure Sensor',   type:'vacuum', ip:'192.168.1.102', description:'0.5-4.5V transducer on PA1' },
      { id:'motor_01', name:'Motor 1 RPM Controller',   type:'motor',  ip:'192.168.1.103', description:'Hall effect on TIM4_CH1 PB6' },
      { id:'motor_02', name:'Motor 2 RPM Controller',   type:'motor2', ip:'192.168.1.104', description:'Hall effect on TIM4_CH2 PB7' },
    ];
    devs.forEach(d => run(`INSERT INTO devices (id,name,type,ip,description) VALUES (?,?,?,?,?)`,
      [d.id, d.name, d.type, d.ip, d.description]));

    const setpoints = [
      { did:'pt100_01', pid:'pt100_temp',  label:'Process Temperature', unit:'°C',  val:80.0 },
      { did:'pt100_01', pid:'cutoff_temp', label:'Over-Temp Cutoff',    unit:'°C',  val:100.0 },
      { did:'vac_01',   pid:'pressure_kpa',label:'Vacuum Pressure',     unit:'kPa', val:-85.0 },
      { did:'motor_01', pid:'rpm',         label:'Motor Speed',         unit:'RPM', val:1500 },
      { did:'motor_01', pid:'current_ma',  label:'Drive Current',       unit:'mA',  val:500 },
      { did:'motor_02', pid:'rpm',         label:'Motor Speed',         unit:'RPM', val:3000 },
      { did:'motor_02', pid:'supply_v',    label:'Supply Voltage',      unit:'V',   val:24.0 },
    ];
    setpoints.forEach(s => run(
      `INSERT INTO device_setpoints (device_id,param_id,param_label,unit,set_value,set_by,set_by_name,reason,esig_verified)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [s.did, s.pid, s.label, s.unit, s.val, 'SYSTEM', 'System', 'Initial system configuration', 1]
    ));
    console.log('[DB] Default devices and setpoints seeded');
  }
  saveDB();
}

// ── Query helpers ─────────────────────────────────────────────────────
function queryAll(sql, params=[]) {
  try {
    const stmt = db.prepare(sql); stmt.bind(params);
    const rows = []; while(stmt.step()) rows.push(stmt.getAsObject()); stmt.free();
    return rows;
  } catch(e) { console.error('[DB] queryAll:', e.message); return []; }
}
function queryOne(sql, params=[]) { return queryAll(sql, params)[0]||null; }
function run(sql, params=[]) {
  try { db.run(sql, params); dbDirty=true; }
  catch(e) { console.error('[DB] run:', e.message); throw e; }
}
function runNow(sql, params=[]) { run(sql, params); saveDB(); }

// ── Save DB ───────────────────────────────────────────────────────────
function saveDB() {
  if (!db) return;
  try {
    const tmp = DB_FILE+'.tmp';
    fs.writeFileSync(tmp, Buffer.from(db.export()));
    fs.renameSync(tmp, DB_FILE);
    dbDirty = false;
  } catch(e) {
    console.error('[DB] Save failed:', e.message);
    try { fs.writeFileSync(DB_FILE, Buffer.from(db.export())); dbDirty=false; } catch {}
  }
}

function pruneReadings() {
  const devs = queryAll('SELECT id FROM devices');
  devs.forEach(d => {
    const c = queryOne('SELECT COUNT(*) as c FROM device_readings WHERE device_id=?',[d.id])?.c||0;
    if (c>10000) run(
      `DELETE FROM device_readings WHERE device_id=? AND id NOT IN
       (SELECT id FROM device_readings WHERE device_id=? ORDER BY id DESC LIMIT 10000)`,
      [d.id, d.id]
    );
  });
  if (dbDirty) saveDB();
}

// ── 21 CFR Audit (tamper-evident, append-only, unique GUID per entry) ──
// FIX items 3, 7: records ALL actions with GUID; NTP timestamp used
function cfr_audit(username, fullName, role, action, targetType, targetId, desc,
                   oldVal='', newVal='', ip='', reason='', esigUser='', esigOk=0, status='success') {
  const guid = uuidv4();                // item 7 — unique GUID per log entry
  const ts   = ntpNow();                // item 8 — NTP-synced UTC timestamp
  // HMAC-SHA256 checksum for tamper detection (stronger than base64)
  const data = `${guid}|${username}|${action}|${targetId}|${desc}|${oldVal}|${newVal}|${ts}`;
  const checksum = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('hex').slice(0,32);
  try {
    db.run(
      `INSERT INTO audit_log
       (guid,timestamp,username,full_name,role,action,target_type,target_id,description,
        old_value,new_value,reason,esig_username,esig_verified,ip_address,status,checksum)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [guid, ts,
       username||'SYSTEM', fullName||'', role||'', action,
       targetType||'', targetId||'', desc||'',
       String(oldVal||''), String(newVal||''),
       reason||'', esigUser||'', esigOk?1:0,
       ip||'', status, checksum]
    );
    dbDirty = true;
    console.log(`[AUDIT] ${ts} | ${guid.slice(0,8)} | ${action} | ${username} | ${desc}`);
  } catch(e) { console.error('[AUDIT] Failed:', e.message); }
}

// ── Password policy validator ─────────────────────────────────────────
function validatePassword(pw) {
  const errors = [];
  if (!pw || pw.length < CFR.PASSWORD_MIN_LENGTH)
    errors.push(`Minimum ${CFR.PASSWORD_MIN_LENGTH} characters`);
  if (CFR.PASSWORD_REQUIRE_UPPER && !/[A-Z]/.test(pw))
    errors.push('At least one uppercase letter (A-Z)');
  if (CFR.PASSWORD_REQUIRE_LOWER && !/[a-z]/.test(pw))
    errors.push('At least one lowercase letter (a-z)');
  if (CFR.PASSWORD_REQUIRE_DIGIT && !/[0-9]/.test(pw))
    errors.push('At least one digit (0-9)');
  if (CFR.PASSWORD_REQUIRE_SPEC  && !/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(pw))
    errors.push('At least one special character (!@#$%^&*)');
  return errors;
}

function checkPasswordHistory(userId, newPw) {
  const history = queryAll(
    'SELECT password FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?',
    [userId, CFR.PASSWORD_HISTORY]
  );
  return history.some(h => bcrypt.compareSync(newPw, h.password));
}

// ── Auth middleware ───────────────────────────────────────────────────
function authMW(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error:'No token' });
  try {
    const user = jwt.verify(h.slice(7), JWT_SECRET);
    // Update last_active for session timeout tracking
    run(`UPDATE sessions SET last_active=datetime('now') WHERE token=?`, [h.slice(7)]);
    // Check session hasn't timed out
    const sess = queryOne('SELECT last_active FROM sessions WHERE token=?', [h.slice(7)]);
    if (sess) {
      const lastActive = new Date(sess.last_active.replace(' ','T')+'Z').getTime();
      if (Date.now() - lastActive > CFR.SESSION_TIMEOUT_MS) {
        run(`DELETE FROM sessions WHERE token=?`, [h.slice(7)]);
        // FIX 6: Auto logout — full audit entry with IP (21 CFR §11.300d)
        cfr_audit(user.username, user.name, user.role, 'session_timeout', 'session',
          user.username,
          `Auto logout — session idle > ${CFR.SESSION_TIMEOUT_MS/60000} min (21 CFR §11.300d)`,
          '', '', req.ip||'');
        console.log(`[SESSION_TIMEOUT] ${user.username} auto-logged out after idle`);
        saveDB();
        return res.status(401).json({ error:'Session expired — please login again', code:'SESSION_TIMEOUT', timeout_min: CFR.SESSION_TIMEOUT_MS/60000 });
      }
    }
    req.user = user;
    req.token = h.slice(7);
    next();
  } catch { res.status(401).json({ error:'Invalid or expired token' }); }
}

function adminOnly(req, res, next) {
  if (!['administrator','factory','qa'].includes(req.user?.role))
    return res.status(403).json({ error:'Administrator or QA access required' });
  next();
}

// Admin/Factory ONLY — audit trail, user management, datalogger delete
function factoryOnly(req, res, next) {
  if (!['administrator','factory'].includes(req.user?.role))
    return res.status(403).json({ error:'Administrator or Factory access required' });
  next();
}

// PURE FACTORY ONLY — device/instrument registration is restricted to the
// factory account exclusively. No other role, including Administrator, can
// add new instruments. This ensures hardware configuration is fully
// controlled and traceable to a single accountable identity.
function pureFactoryOnly(req, res, next) {
  if (req.user?.role !== 'factory')
    return res.status(403).json({
      error: 'Only the Factory account can register new instruments. Contact the factory account holder.',
      code:  'FACTORY_ONLY'
    });
  next();
}

// Supervisor or above (admin/factory/qa/supervisor can read all data and ack alarms)
function supervisorOnly(req, res, next) {
  if (!['administrator','factory','qa','supervisor'].includes(req.user?.role))
    return res.status(403).json({ error:'Supervisor or higher access required' });
  next();
}

// Operator or above (any logged-in user with valid role)
function operatorOnly(req, res, next) {
  if (!['administrator','factory','qa','supervisor','operator'].includes(req.user?.role))
    return res.status(403).json({ error:'Operator or higher access required' });
  next();
}

// Role privilege map — 21 CFR §11.10(d)
const ROLE_PRIVILEGES = {
  administrator: ['read','write','setpoint','create_user','edit_user','delete_user','manage_devices','export','ack_alarm','view_audit','delete_log','data_logger_delete'],
  factory:       ['read','write','setpoint','create_user','edit_user','delete_user','manage_devices','export','ack_alarm','view_audit','delete_log','data_logger_delete'],
  supervisor:    ['read','write','setpoint','export','ack_alarm'],
  qa:            ['read','setpoint','export','ack_alarm','create_user'],
  operator:      ['read','setpoint','export'],
};
function hasPrivilege(role, priv) {
  return (ROLE_PRIVILEGES[role]||[]).includes(priv);
}

// ── Electronic Signature verifier ────────────────────────────────────
// Used for critical actions — re-verifies the user's password
function verifyESig(username, password) {
  const user = queryOne('SELECT * FROM users WHERE username=? AND enabled=1', [username]);
  if (!user) return false;
  return bcrypt.compareSync(password, user.password);
}

// =====================================================================
// 21 CFR AUTH ROUTES
// =====================================================================

// POST /api/login — with account lockout
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username||!password) return res.status(400).json({ error:'Username and password required' });

  const user = queryOne('SELECT * FROM users WHERE username=?', [username]);
  if (!user) {
    cfr_audit(username,'','','login_failed','session',username,'Login failed — user not found','','','',req.ip,'','',0,'failed');
    return res.status(401).json({ error:'Invalid credentials' });
  }

  // Check account locked
  if (user.locked_until) {
    const lockUntil = new Date(user.locked_until.replace(' ','T')+'Z').getTime();
    if (Date.now() < lockUntil) {
      const minsLeft = Math.ceil((lockUntil-Date.now())/60000);
      cfr_audit(username,user.full_name,user.role,'login_blocked','session',username,
        `Login blocked — account locked for ${minsLeft} more minutes`,'','',req.ip,'','',0,'failed');
      return res.status(423).json({ error:`Account locked. Try again in ${minsLeft} minutes.`, code:'ACCOUNT_LOCKED' });
    } else {
      run(`UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?`, [user.id]);
    }
  }

  // Check account enabled
  if (!user.enabled) {
    cfr_audit(username,user.full_name,user.role,'login_failed','session',username,'Login failed — account disabled','','',req.ip,'','',0,'failed');
    return res.status(401).json({ error:'Account disabled. Contact administrator.' });
  }

  // Verify password
  if (!bcrypt.compareSync(password, user.password)) {
    const newAttempts = (user.failed_attempts||0) + 1;
    if (newAttempts >= CFR.MAX_LOGIN_ATTEMPTS) {
      const lockUntil = new Date(Date.now()+CFR.LOCKOUT_DURATION_MS).toISOString().replace('T',' ').slice(0,19);
      run(`UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?`, [newAttempts, lockUntil, user.id]);
      cfr_audit(username,user.full_name,user.role,'account_locked','session',username,
        `Account locked after ${newAttempts} failed attempts`,'','',req.ip,'','',0,'failed');
      saveDB();
      return res.status(423).json({ error:`Account locked for ${CFR.LOCKOUT_DURATION_MS/60000} minutes after ${CFR.MAX_LOGIN_ATTEMPTS} failed attempts.`, code:'ACCOUNT_LOCKED' });
    }
    run(`UPDATE users SET failed_attempts=? WHERE id=?`, [newAttempts, user.id]);
    cfr_audit(username,user.full_name,user.role,'login_failed','session',username,
      `Login failed — wrong password (attempt ${newAttempts}/${CFR.MAX_LOGIN_ATTEMPTS})`,'','',req.ip,'','',0,'failed');
    saveDB();
    return res.status(401).json({ error:`Invalid credentials. ${CFR.MAX_LOGIN_ATTEMPTS-newAttempts} attempt(s) remaining.` });
  }

  // Success — reset failed attempts
  run(`UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?`, [user.id]);

  // Check password expiry
  const pwChanged = new Date(user.password_changed_at.replace(' ','T')+'Z').getTime();
  const pwExpired = (Date.now()-pwChanged) > (CFR.PASSWORD_EXPIRY_DAYS*86400000);
  // FIX 4: Force password change — triggered on first login (must_change_pw=1) or expiry
  if (pwExpired || user.must_change_pw) {
    const reason = user.must_change_pw ? 'First login — temporary password must be changed (21 CFR §11.300)' : 'Password expired after '+CFR.PASSWORD_EXPIRY_DAYS+' days (21 CFR §11.300b)';
    const token = jwt.sign({ id:user.id, username:user.username, role:user.role, name:user.full_name, mustChangePw:true }, JWT_SECRET, { expiresIn:'15m' });
    cfr_audit(user.username,user.full_name,user.role,'force_pw_change','session',user.username, reason,'','',req.ip);
    saveDB();
    console.log(`[LOGIN] ${user.username} — FORCE PASSWORD CHANGE: ${reason}`);
    return res.json({ token, must_change_password:true, must_change_reason: reason, user:{ username:user.username, name:user.full_name, role:user.role, initials:(user.full_name||user.username).split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2) } });
  }

  const token = jwt.sign({ id:user.id, username:user.username, role:user.role, name:user.full_name }, JWT_SECRET, { expiresIn:'8h' });
  const expiresAt = new Date(Date.now()+8*3600000).toISOString().replace('T',' ').slice(0,19);
  runNow(`INSERT INTO sessions (user_id,username,token,ip,expires_at) VALUES (?,?,?,?,?)`,
    [user.id, user.username, token, req.ip, expiresAt]);

  cfr_audit(user.username,user.full_name,user.role,'login','session',user.username,
    `Successful login from ${req.ip}`,'','',req.ip);
  console.log(`[LOGIN] ${user.username} (${user.role}) from ${req.ip}`);
  res.json({
    token,
    user:{ id:user.id, username:user.username, name:user.full_name, email:user.email, role:user.role,
           initials:(user.full_name||user.username).split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2) },
    cfr_policy:{ session_timeout_min:CFR.SESSION_TIMEOUT_MS/60000, password_expiry_days:CFR.PASSWORD_EXPIRY_DAYS }
  });
});

// POST /api/logout
app.post('/api/logout', authMW, (req, res) => {
  run(`DELETE FROM sessions WHERE token=?`, [req.token]);
  cfr_audit(req.user.username,req.user.name,req.user.role,'logout','session',req.user.username,'User logged out','','',req.ip);
  saveDB();
  res.json({ ok:true });
});

// GET /api/me
app.get('/api/me', authMW, (req, res) => {
  const user = queryOne('SELECT id,username,full_name,email,role,created_at,password_changed_at,must_change_pw FROM users WHERE id=?', [req.user.id]);
  if (!user) return res.status(404).json({ error:'User not found' });
  const pwChanged = new Date(user.password_changed_at.replace(' ','T')+'Z').getTime();
  user.password_expires_in_days = Math.max(0, CFR.PASSWORD_EXPIRY_DAYS - Math.floor((Date.now()-pwChanged)/86400000));
  res.json(user);
});

// POST /api/change-password
app.post('/api/change-password', authMW, (req, res) => {
  const { current_password, new_password } = req.body;
  const user = queryOne('SELECT * FROM users WHERE id=?', [req.user.id]);
  if (!user) return res.status(404).json({ error:'User not found' });
  if (!bcrypt.compareSync(current_password, user.password))
    return res.status(401).json({ error:'Current password is incorrect' });

  // Validate new password against policy
  const errors = validatePassword(new_password);
  if (errors.length) return res.status(400).json({ error:'Password policy violation', violations:errors });

  // Check history
  if (checkPasswordHistory(user.id, new_password))
    return res.status(400).json({ error:`Cannot reuse any of your last ${CFR.PASSWORD_HISTORY} passwords` });

  const hashed = bcrypt.hashSync(new_password, 12);
  run(`UPDATE users SET password=?, password_changed_at=datetime('now'), must_change_pw=0, updated_at=datetime('now') WHERE id=?`,
    [hashed, user.id]);
  run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [user.id, hashed]);
  // Keep only last N in history
  const hist = queryAll('SELECT id FROM password_history WHERE user_id=? ORDER BY id DESC', [user.id]);
  if (hist.length > CFR.PASSWORD_HISTORY)
    hist.slice(CFR.PASSWORD_HISTORY).forEach(h => run('DELETE FROM password_history WHERE id=?', [h.id]));

  cfr_audit(user.username,user.full_name,user.role,'password_change','user',user.username,
    'Password changed successfully','','',req.ip);
  saveDB();
  res.json({ ok:true, message:'Password changed. New password valid for '+CFR.PASSWORD_EXPIRY_DAYS+' days.' });
});

// POST /api/verify-esig — verify electronic signature (re-auth)
app.post('/api/verify-esig', authMW, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error:'Password required for electronic signature' });
  const ok = verifyESig(req.user.username, password);
  if (!ok) {
    cfr_audit(req.user.username,req.user.name,req.user.role,'esig_failed','esig',req.user.username,
      'Electronic signature verification failed','','',req.ip,'','',0,'failed');
    return res.status(401).json({ error:'Electronic signature invalid', ok:false });
  }
  cfr_audit(req.user.username,req.user.name,req.user.role,'esig_verified','esig',req.user.username,
    'Electronic signature verified','','',req.ip);
  res.json({ ok:true });
});

// =====================================================================
// DEVICES
// =====================================================================
app.get('/api/devices', authMW, (req, res) => {
  const devs = queryAll('SELECT * FROM devices ORDER BY created_at');
  devs.forEach(d => {
    const latest = queryOne('SELECT payload,timestamp FROM device_readings WHERE device_id=? ORDER BY id DESC LIMIT 1', [d.id]);
    const count  = queryOne('SELECT COUNT(*) as c FROM device_readings WHERE device_id=?', [d.id]);
    const sps    = queryAll('SELECT * FROM device_setpoints WHERE device_id=? AND is_current=1 ORDER BY param_id', [d.id]);
    d.latest        = latest ? JSON.parse(latest.payload) : null;
    d.last_seen     = latest ? latest.timestamp : null;
    d.reading_count = count?.c||0;
    d.ingest_url    = `/api/device/${d.id}/ingest`;
    d.setpoints     = sps;
    d.online        = latest ? (Date.now()-new Date(latest.timestamp.replace(' ','T')+'Z').getTime())<10000 : false;
  });
  res.json(devs);
});

app.post('/api/devices', authMW, pureFactoryOnly, (req, res) => {
  const { id, name, type, ip, description } = req.body;
  if (!id||!name) return res.status(400).json({ error:'id and name required' });
  if (!/^[a-zA-Z0-9_]+$/.test(id)) return res.status(400).json({ error:'ID: alphanumeric + underscores only' });
  if (queryOne('SELECT id FROM devices WHERE id=?', [id])) return res.status(409).json({ error:`ID "${id}" exists` });
  run(`INSERT INTO devices (id,name,type,ip,description,created_by) VALUES (?,?,?,?,?,?)`,
    [id, name, type||'generic', ip||'', description||'', req.user.username]);
  cfr_audit(req.user.username,req.user.name,req.user.role,'create_device','device',id,
    `Registered device: ${name}`,'',JSON.stringify({id,name,type,ip}),req.ip);
  saveDB();
  res.status(201).json({ ok:true, id, ingest_url:`/api/device/${id}/ingest` });
});

app.delete('/api/devices/:id', authMW, adminOnly, (req, res) => {
  const { id } = req.params;
  const { esig_password, reason } = req.body;
  if (!reason) return res.status(400).json({ error:'Reason required for device deletion (21 CFR Part 11)' });
  if (!verifyESig(req.user.username, esig_password))
    return res.status(401).json({ error:'Electronic signature required for device deletion' });
  const before = queryOne('SELECT name,type,ip FROM devices WHERE id=?', [id]);
  if (!before) return res.status(404).json({ error:'Device not found' });
  run(`UPDATE devices SET enabled=0 WHERE id=?`, [id]); // soft-delete only
  cfr_audit(req.user.username,req.user.name,req.user.role,'delete_device','device',id,
    `Device disabled: ${id} — ${reason}`,JSON.stringify(before),'',req.ip,reason,req.user.username,1);
  saveDB();
  res.json({ ok:true });
});

// =====================================================================
// SETPOINTS — with electronic signature + reason for change
// =====================================================================
// =====================================================================
// DEVICE-FACING SETPOINTS — no JWT (STM32 cannot do interactive login)
// Mirrors the security model of /ingest: device must exist + be enabled.
// Separate path (/device-setpoints) so it never collides with the
// authenticated dashboard route below (both would otherwise match
// "/api/device/:id/setpoints" and only the first-registered would fire).
// Returns a FLAT JSON object { param_id: set_value, ... } which is what
// the firmware's JsonExtractFloat()/JsonExtractBool() parser expects.
// =====================================================================
app.get('/api/device/:deviceId/device-setpoints', (req, res) => {
  const { deviceId } = req.params;
  const device = queryOne('SELECT * FROM devices WHERE id=? AND enabled=1', [deviceId]);
  if (!device) return res.status(404).json({ error: `Device "${deviceId}" not found` });

  const rows = queryAll(
    'SELECT param_id, set_value FROM device_setpoints WHERE device_id=? AND is_current=1',
    [deviceId]
  );
  const flat = {};
  rows.forEach(r => { flat[r.param_id] = r.set_value; });

  // Optional: track that the device actually polled (useful for "online" status)
  run(`UPDATE devices SET last_seen=datetime('now') WHERE id=?`, [deviceId]);
  saveDB();

  res.json(flat);
});

// Authenticated, richer version for the web dashboard (full row detail)
app.get('/api/device/:id/setpoints', authMW, (req, res) => {
  res.json(queryAll('SELECT * FROM device_setpoints WHERE device_id=? AND is_current=1 ORDER BY param_id', [req.params.id]));
});

app.get('/api/device/:id/setpoints/history', authMW, (req, res) => {
  res.json(queryAll('SELECT * FROM device_setpoints WHERE device_id=? ORDER BY id DESC LIMIT 200', [req.params.id]));
});

// POST /api/device/:id/setpoint — 21 CFR: requires reason + e-signature
app.post('/api/device/:deviceId/setpoint', authMW, (req, res) => {
  const { deviceId } = req.params;
  const { param_id, param_label, unit, value, reason, esig_password } = req.body;

  if (!param_id || value===undefined) return res.status(400).json({ error:'param_id and value required' });
  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error:'Reason for change required (min 5 characters) — 21 CFR Part 11', code:'REASON_REQUIRED' });
  // FIX 5: E-sig verification with full audit trail (21 CFR §11.50)
  if (CFR.REQUIRE_ESIG) {
    if (!esig_password) {
      cfr_audit(req.user.username,req.user.name,req.user.role,'esig_failed','setpoint',`${deviceId}/${param_id}`,
        'E-signature attempted without password','','',req.ip,reason,'',0,'failed');
      return res.status(401).json({ error:'Electronic signature password required (21 CFR §11.50)', code:'ESIG_REQUIRED' });
    }
    if (!verifyESig(req.user.username, esig_password)) {
      cfr_audit(req.user.username,req.user.name,req.user.role,'esig_failed','setpoint',`${deviceId}/${param_id}`,
        `E-signature verification failed for setpoint change on ${deviceId}/${param_id}`,'','',req.ip,reason,'',0,'failed');
      return res.status(401).json({ error:'Electronic signature (password) invalid — 21 CFR Part 11', code:'ESIG_REQUIRED' });
    }
    // Log successful e-sig verification
    cfr_audit(req.user.username,req.user.name,req.user.role,'esig_verified','setpoint',`${deviceId}/${param_id}`,
      `E-signature verified for ${param_label||param_id} change on ${deviceId}`,'','',req.ip,reason,req.user.username,1);
  }

  const device = queryOne('SELECT * FROM devices WHERE id=? AND enabled=1', [deviceId]);
  if (!device) return res.status(404).json({ error:'Device not found' });

  const prev = queryOne('SELECT set_value FROM device_setpoints WHERE device_id=? AND param_id=? AND is_current=1', [deviceId, param_id]);
  const oldVal = prev ? prev.set_value : null;
  const newVal = parseFloat(value);

  // Mark previous as not current
  run(`UPDATE device_setpoints SET is_current=0 WHERE device_id=? AND param_id=?`, [deviceId, param_id]);

  // Insert new setpoint (append-only — full history preserved)
  run(`INSERT INTO device_setpoints (device_id,param_id,param_label,unit,set_value,set_by,set_by_name,reason,esig_verified,is_current)
       VALUES (?,?,?,?,?,?,?,?,1,1)`,
    [deviceId, param_id, param_label||param_id, unit||'', newVal, req.user.username, req.user.name, reason.trim()]);

  // 21 CFR audit with e-signature record
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'set_value', 'setpoint', `${deviceId}/${param_id}`,
    `Setpoint changed: ${param_label||param_id} on [${deviceId}] from ${oldVal} to ${newVal} ${unit||''}`,
    oldVal!==null ? String(oldVal) : 'N/A', String(newVal),
    req.ip, reason.trim(), req.user.username, 1
  );
  saveDB();
  console.log(`[SET] ${deviceId}/${param_id}: ${oldVal} → ${newVal} by ${req.user.username} | Reason: ${reason}`);
  res.json({ ok:true, device_id:deviceId, param_id, old_value:oldVal, new_value:newVal, set_by:req.user.username, reason });
});

// =====================================================================
// PROFILES — Recipe Programming (multi-device setpoint bundles)
// 21 CFR Part 11: create/edit is operator+; starting a profile requires
// a reason + electronic signature exactly like a manual setpoint change.
// Each item inside the profile is written and audited individually
// (identical audit_log shape to /setpoint), plus one summary
// 'profile_run' record + profile_runs row ties the batch together for
// traceability back to a single signed action.
// =====================================================================
function loadProfileItems(profileId) {
  return queryAll('SELECT * FROM profile_items WHERE profile_id=? ORDER BY sort_order,id', [profileId]);
}
function serializeProfile(p) {
  const items   = loadProfileItems(p.id);
  const lastRun = queryOne(
    'SELECT run_at,run_by,run_by_name,applied_count,failed_count FROM profile_runs WHERE profile_id=? ORDER BY id DESC LIMIT 1',
    [p.id]
  );
  return { ...p, items, item_count: items.length, last_run: lastRun || null };
}
function validateProfileItems(items) {
  if (!Array.isArray(items) || items.length === 0) return 'At least one setpoint item is required';
  for (const it of items) {
    if (!it.device_id || !it.param_id || it.value === undefined || it.value === '' || isNaN(parseFloat(it.value)))
      return 'Each item needs device_id, param_id, and a numeric value';
    if (!queryOne('SELECT id FROM devices WHERE id=? AND enabled=1', [it.device_id]))
      return `Device "${it.device_id}" not found or disabled`;
  }
  return null;
}

// GET all profiles (not deleted)
app.get('/api/profiles', authMW, operatorOnly, (req, res) => {
  const profiles = queryAll('SELECT * FROM profiles WHERE deleted=0 ORDER BY created_at DESC');
  res.json(profiles.map(serializeProfile));
});

// GET the currently active profile (if any) — must be registered before /:id
app.get('/api/profiles/active', authMW, operatorOnly, (req, res) => {
  const p = queryOne('SELECT * FROM profiles WHERE is_active=1 AND deleted=0');
  if (!p) return res.json({ active: false, profile: null });
  res.json({ active: true, profile: serializeProfile(p) });
});

// Clear the active-profile flag (dashboard indicator only — no device/setpoint change,
// so no e-signature is required, just an authenticated user)
app.post('/api/profiles/clear-active', authMW, operatorOnly, (req, res) => {
  const wasActive = queryOne('SELECT * FROM profiles WHERE is_active=1 AND deleted=0');
  run(`UPDATE profiles SET is_active=0`);
  if (wasActive) {
    cfr_audit(req.user.username, req.user.name, req.user.role,
      'clear_active_profile', 'profile', wasActive.guid,
      `Active profile indicator cleared: "${wasActive.name}" (no device values changed)`, '', '', req.ip);
    saveDB();
  }
  res.json({ ok: true });
});

// GET one profile
app.get('/api/profiles/:id', authMW, operatorOnly, (req, res) => {
  const p = queryOne('SELECT * FROM profiles WHERE id=? AND deleted=0', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  res.json(serializeProfile(p));
});

// GET run history for a profile
app.get('/api/profiles/:id/runs', authMW, operatorOnly, (req, res) => {
  res.json(queryAll('SELECT * FROM profile_runs WHERE profile_id=? ORDER BY id DESC LIMIT 100', [req.params.id]));
});

// CREATE profile
app.post('/api/profiles', authMW, operatorOnly, (req, res) => {
  const { name, description, items } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Profile name required' });
  const err = validateProfileItems(items);
  if (err) return res.status(400).json({ error: err });

  const guid = uuidv4();
  run(`INSERT INTO profiles (guid,name,description,created_by,created_by_name) VALUES (?,?,?,?,?)`,
    [guid, name.trim(), (description || '').trim(), req.user.username, req.user.name]);
  const prof = queryOne('SELECT id FROM profiles WHERE guid=?', [guid]);
  items.forEach((it, idx) => run(
    `INSERT INTO profile_items (profile_id,device_id,param_id,param_label,unit,value,sort_order)
     VALUES (?,?,?,?,?,?,?)`,
    [prof.id, it.device_id, it.param_id, it.param_label || it.param_id, it.unit || '', parseFloat(it.value), idx]
  ));
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'create_profile', 'profile', guid,
    `Profile created: "${name.trim()}" — ${items.length} setpoint(s) across ${new Set(items.map(i => i.device_id)).size} device(s)`,
    '', JSON.stringify(items), req.ip);
  saveDB();
  res.status(201).json(serializeProfile(queryOne('SELECT * FROM profiles WHERE id=?', [prof.id])));
});

// EDIT profile (replaces all items)
app.put('/api/profiles/:id', authMW, operatorOnly, (req, res) => {
  const { name, description, items } = req.body || {};
  const p = queryOne('SELECT * FROM profiles WHERE id=? AND deleted=0', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  if (!name || !name.trim()) return res.status(400).json({ error: 'Profile name required' });
  const err = validateProfileItems(items);
  if (err) return res.status(400).json({ error: err });

  const before = loadProfileItems(p.id);
  run(`UPDATE profiles SET name=?,description=?,updated_at=datetime('now') WHERE id=?`,
    [name.trim(), (description || '').trim(), p.id]);
  run(`DELETE FROM profile_items WHERE profile_id=?`, [p.id]);
  items.forEach((it, idx) => run(
    `INSERT INTO profile_items (profile_id,device_id,param_id,param_label,unit,value,sort_order)
     VALUES (?,?,?,?,?,?,?)`,
    [p.id, it.device_id, it.param_id, it.param_label || it.param_id, it.unit || '', parseFloat(it.value), idx]
  ));
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'edit_profile', 'profile', p.guid,
    `Profile edited: "${name.trim()}" — ${items.length} setpoint(s)`,
    JSON.stringify(before), JSON.stringify(items), req.ip);
  saveDB();
  res.json(serializeProfile(queryOne('SELECT * FROM profiles WHERE id=?', [p.id])));
});

// DELETE profile — Factory/Administrator only, reason required (soft delete)
app.delete('/api/profiles/:id', authMW, factoryOnly, (req, res) => {
  const { reason } = req.body || {};
  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error: 'Reason required (min 5 characters)', code: 'REASON_REQUIRED' });
  const p = queryOne('SELECT * FROM profiles WHERE id=? AND deleted=0', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  run(`UPDATE profiles SET deleted=1,deleted_by=?,deleted_at=datetime('now'),delete_reason=? WHERE id=?`,
    [req.user.username, reason.trim(), p.id]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'delete_profile', 'profile', p.guid,
    `Profile deleted: "${p.name}" — reason: ${reason.trim()}`,
    '', '', req.ip, reason.trim(), req.user.username, 1);
  saveDB();
  res.json({ ok: true });
});

// START profile — signs and applies every item as a real setpoint change
app.post('/api/profiles/:id/start', authMW, operatorOnly, (req, res) => {
  const { reason, esig_password } = req.body || {};
  const p = queryOne('SELECT * FROM profiles WHERE id=? AND deleted=0', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Profile not found' });
  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error: 'Reason for change required (min 5 characters) — 21 CFR Part 11', code: 'REASON_REQUIRED' });
  if (!esig_password) {
    cfr_audit(req.user.username, req.user.name, req.user.role, 'esig_failed', 'profile', p.guid,
      `E-signature attempted without password for profile start: "${p.name}"`, '', '', req.ip, reason || '', '', 0, 'failed');
    return res.status(401).json({ error: 'Electronic signature password required (21 CFR §11.50)', code: 'ESIG_REQUIRED' });
  }
  if (!verifyESig(req.user.username, esig_password)) {
    cfr_audit(req.user.username, req.user.name, req.user.role, 'esig_failed', 'profile', p.guid,
      `E-signature verification failed for profile start: "${p.name}"`, '', '', req.ip, reason, '', 0, 'failed');
    return res.status(401).json({ error: 'Electronic signature (password) invalid — 21 CFR Part 11', code: 'ESIG_REQUIRED' });
  }
  cfr_audit(req.user.username, req.user.name, req.user.role, 'esig_verified', 'profile', p.guid,
    `E-signature verified for profile start: "${p.name}"`, '', '', req.ip, reason, req.user.username, 1);

  const items = loadProfileItems(p.id);
  const results = [];
  items.forEach(it => {
    const device = queryOne('SELECT id FROM devices WHERE id=? AND enabled=1', [it.device_id]);
    if (!device) { results.push({ device_id: it.device_id, param_id: it.param_id, ok: false, error: 'device not found/disabled' }); return; }
    const prev   = queryOne('SELECT set_value FROM device_setpoints WHERE device_id=? AND param_id=? AND is_current=1', [it.device_id, it.param_id]);
    const oldVal = prev ? prev.set_value : null;
    const newVal = it.value;

    run(`UPDATE device_setpoints SET is_current=0 WHERE device_id=? AND param_id=?`, [it.device_id, it.param_id]);
    run(`INSERT INTO device_setpoints (device_id,param_id,param_label,unit,set_value,set_by,set_by_name,reason,esig_verified,is_current)
         VALUES (?,?,?,?,?,?,?,?,1,1)`,
      [it.device_id, it.param_id, it.param_label || it.param_id, it.unit || '', newVal, req.user.username, req.user.name,
       `[Profile: ${p.name}] ${reason.trim()}`]);

    cfr_audit(req.user.username, req.user.name, req.user.role,
      'set_value', 'setpoint', `${it.device_id}/${it.param_id}`,
      `Setpoint changed via profile "${p.name}": ${it.param_label || it.param_id} on [${it.device_id}] from ${oldVal} to ${newVal} ${it.unit || ''}`,
      oldVal !== null ? String(oldVal) : 'N/A', String(newVal),
      req.ip, reason.trim(), req.user.username, 1);

    results.push({ device_id: it.device_id, param_id: it.param_id, param_label: it.param_label, unit: it.unit, old_value: oldVal, new_value: newVal, ok: true });
  });

  const runGuid       = uuidv4();
  const appliedCount  = results.filter(r => r.ok).length;
  const failedCount   = results.length - appliedCount;
  run(`INSERT INTO profile_runs (guid,profile_id,profile_name,run_by,run_by_name,reason,item_count,applied_count,failed_count,ip_address,details)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [runGuid, p.id, p.name, req.user.username, req.user.name, reason.trim(), items.length, appliedCount, failedCount, req.ip, JSON.stringify(results)]);

  // Mark this profile as the dashboard's "active profile" (only one at a time)
  if (appliedCount > 0) {
    run(`UPDATE profiles SET is_active=0`);
    run(`UPDATE profiles SET is_active=1 WHERE id=?`, [p.id]);
  }

  cfr_audit(req.user.username, req.user.name, req.user.role,
    'profile_run', 'profile', p.guid,
    `Profile started: "${p.name}" — ${appliedCount}/${items.length} setpoint(s) applied`,
    '', JSON.stringify(results), req.ip, reason.trim(), req.user.username, 1);

  saveDB();
  console.log(`[PROFILE] "${p.name}" started by ${req.user.username} — ${appliedCount}/${items.length} applied`);
  res.json({ ok: true, run_guid: runGuid, applied_count: appliedCount, failed_count: failedCount, results });
});

// =====================================================================
// INGEST — STM32 POSTs sensor data
// =====================================================================
app.post('/api/device/:deviceId/ingest', (req, res) => {
  const { deviceId } = req.params;
  const payload = req.body;
  const ip = req.ip;
  const device = queryOne('SELECT * FROM devices WHERE id=? AND enabled=1', [deviceId]);
  if (!device) return res.status(404).json({ error:`Device "${deviceId}" not found` });
  if (!payload||!Object.keys(payload).length) return res.status(400).json({ error:'Empty payload' });
  run(`INSERT INTO device_readings (device_id,payload,source_ip) VALUES (?,?,?)`,
    [deviceId, JSON.stringify(payload), ip]);
  run(`UPDATE devices SET last_seen=datetime('now') WHERE id=?`, [deviceId]);
  checkAlerts(deviceId, device.name, payload);
  saveDB();
  const s = Object.entries(payload).slice(0,4).map(([k,v])=>`${k}=${v}`).join(' ');
  console.log(`[${deviceId}] ${s}`);
  res.json({ ok:true, device:deviceId, ts:new Date().toISOString() });
});

function checkAlerts(deviceId, name, d) {
  const p = `[${name}]`;
  if (d.pt100_temp>100)
    run(`INSERT INTO alerts (device_id,type,message,value,threshold) VALUES (?,?,?,?,?)`,
      [deviceId,'TEMP_HIGH',`${p} Temp ${d.pt100_temp}°C > 100°C limit`,d.pt100_temp,100]);
  if (d.pressure_kpa!==undefined&&Math.abs(d.pressure_kpa)<50)
    run(`INSERT INTO alerts (device_id,type,message,value,threshold) VALUES (?,?,?,?,?)`,
      [deviceId,'LOW_VACUUM',`${p} Vacuum low: ${d.pressure_kpa} kPa`,d.pressure_kpa,-50]);
  if (d.current_ma>550)
    run(`INSERT INTO alerts (device_id,type,message,value,threshold) VALUES (?,?,?,?,?)`,
      [deviceId,'HIGH_CURRENT',`${p} Current ${d.current_ma}mA > 550mA`,d.current_ma,550]);
}

// =====================================================================
// SENSOR READ API
// =====================================================================
app.get('/api/device/:id/latest', authMW, (req, res) => {
  const row = queryOne('SELECT payload,timestamp,source_ip FROM device_readings WHERE device_id=? ORDER BY id DESC LIMIT 1', [req.params.id]);
  if (!row) return res.json({ error:'No data yet' });
  res.json({ ...JSON.parse(row.payload), _timestamp:row.timestamp, _ip:row.source_ip });
});

app.get('/api/device/:id/history', authMW, operatorOnly, (req, res) => {
  const mins  = Math.min(parseInt(req.query.minutes)||60, 1440);
  const limit = Math.min(parseInt(req.query.limit)||200, 2000);
  const rows  = queryAll(
    `SELECT payload,timestamp FROM device_readings WHERE device_id=?
     AND timestamp>=datetime('now','-${mins} minutes') ORDER BY id DESC LIMIT ?`,
    [req.params.id, limit]
  );
  res.json(rows.reverse().map(r=>({...JSON.parse(r.payload),_timestamp:r.timestamp})));
});

app.get('/api/devices/all-latest', authMW, (req, res) => {
  const devs = queryAll('SELECT * FROM devices WHERE enabled=1');
  const out = {};
  devs.forEach(d => {
    const row = queryOne('SELECT payload,timestamp FROM device_readings WHERE device_id=? ORDER BY id DESC LIMIT 1', [d.id]);
    const sps = queryAll('SELECT param_id,set_value,param_label,unit FROM device_setpoints WHERE device_id=? AND is_current=1', [d.id]);
    const spMap = {}; sps.forEach(s=>{ spMap[s.param_id]=s.set_value; });
    out[d.id] = {
      device:    d,
      data:      row ? JSON.parse(row.payload) : null,
      timestamp: row ? row.timestamp : null,
      setpoints: spMap,
      online:    row ? (Date.now()-new Date(row.timestamp.replace(' ','T')+'Z').getTime())<10000 : false
    };
  });
  res.json(out);
});

// =====================================================================
// ALERTS
// =====================================================================
app.get('/api/alerts', authMW, (req, res) => {
  const { device } = req.query;
  const sql = device
    ? 'SELECT * FROM alerts WHERE device_id=? AND acknowledged=0 ORDER BY id DESC LIMIT 100'
    : 'SELECT * FROM alerts WHERE acknowledged=0 ORDER BY id DESC LIMIT 100';
  res.json(queryAll(sql, device?[device]:[]));
});

app.post('/api/alerts/:id/ack', authMW, supervisorOnly, (req, res) => {
  const { reason } = req.body;
  if (!reason) return res.status(400).json({ error:'Reason required for alert acknowledgement' });
  const a = queryOne('SELECT type,message,device_id FROM alerts WHERE id=?', [req.params.id]);
  run(`UPDATE alerts SET acknowledged=1,ack_by=?,ack_at=datetime('now'),ack_reason=? WHERE id=?`,
    [req.user.username, reason, req.params.id]);
  cfr_audit(req.user.username,req.user.name,req.user.role,'ack_alert','alert',req.params.id,
    `Alert acknowledged: ${a?.message||''}`, 'unacknowledged','acknowledged',req.ip,reason);
  saveDB();
  res.json({ ok:true });
});

// =====================================================================
// USERS — full management from database
// =====================================================================
app.get('/api/users', authMW, factoryOnly, (req, res) => {
  const users = queryAll('SELECT id,username,full_name,email,role,enabled,is_protected,audit_access,failed_attempts,locked_until,password_changed_at,must_change_pw,created_at,created_by FROM users ORDER BY id');
  users.forEach(u => {
    const pwChanged = new Date(u.password_changed_at.replace(' ','T')+'Z').getTime();
    u.password_expires_in_days = Math.max(0, CFR.PASSWORD_EXPIRY_DAYS-Math.floor((Date.now()-pwChanged)/86400000));
    u.is_locked = u.locked_until && new Date(u.locked_until.replace(' ','T')+'Z').getTime() > Date.now();
  });
  res.json(users);
});

app.post('/api/users', authMW, factoryOnly, (req, res) => {
  const { username, password, full_name, email, role } = req.body;
  if (!username||!password||!full_name) return res.status(400).json({ error:'username, password and full_name required' });
  if (queryOne('SELECT id FROM users WHERE username=?', [username])) return res.status(409).json({ error:'Username already exists' });
  const errors = validatePassword(password);
  if (errors.length) return res.status(400).json({ error:'Password policy violation', violations:errors });
  const hashed = bcrypt.hashSync(password, 12);
  run(`INSERT INTO users (username,password,full_name,email,role,must_change_pw,created_by) VALUES (?,?,?,?,?,1,?)`,
    [username, hashed, full_name, email||'', role||'operator', req.user.username]);
  const newUser = queryOne('SELECT id FROM users WHERE username=?', [username]);
  run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [newUser.id, hashed]);
  cfr_audit(req.user.username,req.user.name,req.user.role,'create_user','user',username,
    `Created user: ${username} (${role})`, '',JSON.stringify({username,full_name,email,role}),req.ip);
  saveDB();
  res.status(201).json({ ok:true });
});

app.put('/api/users/:id', authMW, factoryOnly, (req, res) => {
  const user = queryOne('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error:'User not found' });
  const { full_name, email, role, enabled, password } = req.body;

  // ABSOLUTE BLOCK: factory account cannot be demoted, disabled, or have role changed
  if (user.is_protected) {
    if (role && role !== user.role)
      return res.status(403).json({ error:'The factory account role cannot be changed', code:'PROTECTED_ACCOUNT' });
    if (enabled === false)
      return res.status(403).json({ error:'The factory account cannot be disabled', code:'PROTECTED_ACCOUNT' });
  }

  // Guard: don't allow demoting/disabling the last admin account
  const losingAdminRole = user.role === 'administrator' &&
    ((role && role !== 'administrator') || enabled === false);
  if (losingAdminRole) {
    const remainingAdmins = queryOne(
      `SELECT COUNT(*) c FROM users WHERE role='administrator' AND enabled=1 AND id!=?`,
      [user.id]
    ).c;
    if (remainingAdmins === 0)
      return res.status(400).json({ error:'Cannot demote/disable the last remaining Administrator account' });
  }

  if (password) {
    const errors = validatePassword(password);
    if (errors.length) return res.status(400).json({ error:'Password policy violation', violations:errors });
    if (checkPasswordHistory(user.id, password)) return res.status(400).json({ error:`Cannot reuse last ${CFR.PASSWORD_HISTORY} passwords` });
    const hashed = bcrypt.hashSync(password, 12);
    run(`UPDATE users SET password=?,password_changed_at=datetime('now'),must_change_pw=0,updated_at=datetime('now') WHERE id=?`, [hashed, user.id]);
    run(`INSERT INTO password_history (user_id,password) VALUES (?,?)`, [user.id, hashed]);
  }
  if (enabled!==undefined) run(`UPDATE users SET enabled=?,updated_at=datetime('now') WHERE id=?`, [enabled?1:0, user.id]);
  run(`UPDATE users SET full_name=COALESCE(?,full_name),email=COALESCE(?,email),role=COALESCE(?,role),updated_at=datetime('now') WHERE id=?`,
    [full_name,email,role,user.id]);
  cfr_audit(req.user.username,req.user.name,req.user.role,'update_user','user',user.username,
    `Updated user: ${user.username}`,
    JSON.stringify({role:user.role,enabled:user.enabled,full_name:user.full_name,email:user.email}),
    JSON.stringify({role:role||user.role,enabled,full_name,email,password_changed:!!password}),req.ip);
  saveDB();
  res.json({ ok:true });
});

// DELETE user — admin/factory only. Permanently disables + tombstones the
// account rather than hard-deleting the row, so historical audit_log,
// device_setpoints, and incidents entries that reference the username
// remain intact (21 CFR §11.10c — record integrity over time).
app.delete('/api/users/:id', authMW, factoryOnly, (req, res) => {
  const { reason } = req.body || {};
  const user = queryOne('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error:'User not found' });

  // ABSOLUTE BLOCK: protected accounts (factory) can never be deleted by anyone
  if (user.is_protected)
    return res.status(403).json({ error:'The factory account is protected and cannot be deleted by anyone', code:'PROTECTED_ACCOUNT' });

  if (user.id === req.user.id)
    return res.status(400).json({ error:'You cannot delete your own account while logged in' });

  const remainingAdmins = queryOne(
    `SELECT COUNT(*) c FROM users WHERE role IN ('administrator','factory') AND enabled=1 AND id!=?`,
    [user.id]
  ).c;
  if (user.role === 'administrator' && remainingAdmins === 0)
    return res.status(400).json({ error:'Cannot delete the last remaining Administrator account' });

  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error:'Reason for deletion required (min 5 characters) — 21 CFR Part 11', code:'REASON_REQUIRED' });

  // Tombstone: disable + rename to free up the username, keep row for audit linkage
  const tombUsername = `${user.username}__deleted_${Date.now()}`;
  run(`UPDATE users SET enabled=0, username=?, updated_at=datetime('now') WHERE id=?`, [tombUsername, user.id]);
  run(`DELETE FROM sessions WHERE user_id=?`, [user.id]);

  cfr_audit(req.user.username, req.user.name, req.user.role,
    'delete_user', 'user', user.username,
    `User deleted: ${user.username} (${user.role}) — reason: ${reason.trim()}`,
    JSON.stringify({username:user.username,role:user.role,enabled:1}),
    JSON.stringify({username:tombUsername,enabled:0}),
    req.ip, reason.trim());
  saveDB();
  res.json({ ok:true, message:`User ${user.username} deleted and sessions revoked` });
});

app.post('/api/users/:id/unlock', authMW, factoryOnly, (req, res) => {
  const user = queryOne('SELECT username,full_name,role FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error:'User not found' });
  run(`UPDATE users SET locked_until=NULL,failed_attempts=0,updated_at=datetime('now') WHERE id=?`, [req.params.id]);
  cfr_audit(req.user.username,req.user.name,req.user.role,'unlock_user','user',user.username,
    `Account unlocked by ${req.user.username}`,'locked','unlocked',req.ip);
  saveDB();
  res.json({ ok:true });
});

// =====================================================================
// 21 CFR AUDIT TRAIL — read-only, tamper-evident
// =====================================================================
// ── Audit access middleware: admin/factory always have access.
// Other users can be granted access by admin/factory via
// POST /api/users/:id/grant-audit  (21 CFR §11.10d).
function auditAccessMW(req, res, next) {
  if (!req.user) return res.status(401).json({ error:'Not authenticated' });
  if (['administrator','factory'].includes(req.user.role)) return next();
  // Check if this user has been explicitly granted audit access
  const u = queryOne('SELECT audit_access FROM users WHERE id=?', [req.user.id]);
  if (u && u.audit_access === 1) return next();
  return res.status(403).json({
    error: 'Audit trail access restricted to Administrator and Factory accounts. Contact your administrator to request access.',
    code: 'AUDIT_ACCESS_DENIED'
  });
}

// Grant audit access to a user (admin/factory only)
app.post('/api/users/:id/grant-audit', authMW, factoryOnly, (req, res) => {
  const user = queryOne('SELECT id,username,role FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error:'User not found' });
  run(`UPDATE users SET audit_access=1 WHERE id=?`, [user.id]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'grant_audit_access', 'user', user.username,
    `Audit trail access GRANTED to ${user.username} (${user.role}) by ${req.user.username}`,
    '0', '1', req.ip);
  saveDB();
  res.json({ ok:true, message:`Audit trail access granted to ${user.username}` });
});

// Revoke audit access from a user (admin/factory only)
app.post('/api/users/:id/revoke-audit', authMW, factoryOnly, (req, res) => {
  const user = queryOne('SELECT id,username,role FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error:'User not found' });
  if (['administrator','factory'].includes(user.role))
    return res.status(400).json({ error:'Cannot revoke audit access from Administrator or Factory accounts' });
  run(`UPDATE users SET audit_access=0 WHERE id=?`, [user.id]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'revoke_audit_access', 'user', user.username,
    `Audit trail access REVOKED from ${user.username} (${user.role}) by ${req.user.username}`,
    '1', '0', req.ip);
  saveDB();
  res.json({ ok:true, message:`Audit trail access revoked from ${user.username}` });
});

app.get('/api/audit', authMW, auditAccessMW, (req, res) => {
  const { username, action, search, from, to, limit=50, offset=0 } = req.query;
  let sql='SELECT * FROM audit_log WHERE 1=1', p=[];
  // Factory role sees only actions performed by admin/factory roles (not operator/supervisor/qa)
  if (req.user.role === 'factory') {
    const topUsers = queryAll(`SELECT username FROM users WHERE role IN ('administrator','factory')`).map(u => u.username);
    if (topUsers.length > 0) {
      sql += ' AND username IN (' + topUsers.map(() => '?').join(',') + ')';
      p.push(...topUsers);
    }
  }
  if (username)   { sql+=' AND username=?';   p.push(username); }
  if (action)     { sql+=' AND action=?';     p.push(action); }
  if (from)       { sql+=' AND timestamp>=?'; p.push(from); }
  if (to)         { sql+=' AND timestamp<=?'; p.push(to); }
  if (search)     {
    sql+=' AND (username LIKE ? OR description LIKE ? OR action LIKE ? OR target_id LIKE ? OR reason LIKE ?)';
    const s=`%${search}%`; p.push(s,s,s,s,s);
  }
  const total = queryOne(sql.replace('SELECT *','SELECT COUNT(*) as c'), p)?.c||0;
  sql+=' ORDER BY id DESC LIMIT ? OFFSET ?';
  p.push(Math.min(Number(limit),500), Number(offset));
  res.json({ total, limit:Number(limit), offset:Number(offset), events:queryAll(sql,p) });
});

app.get('/api/audit/summary', authMW, auditAccessMW, (req, res) => {
  const total    = queryOne('SELECT COUNT(*) as c FROM audit_log')?.c||0;
  const byAction = queryAll('SELECT action, COUNT(*) as count FROM audit_log GROUP BY action ORDER BY count DESC');
  const byUser   = queryAll('SELECT username, COUNT(*) as count FROM audit_log WHERE username!=? GROUP BY username ORDER BY count DESC LIMIT 10',['SYSTEM']);
  const recent   = queryAll('SELECT * FROM audit_log ORDER BY id DESC LIMIT 10');
  res.json({ total, by_action:byAction, by_user:byUser, recent });
});

app.get('/api/audit/users',   authMW, auditAccessMW, (req, res) => res.json(queryAll('SELECT DISTINCT username FROM audit_log WHERE username!=? ORDER BY username',['SYSTEM'])));
app.get('/api/audit/actions', authMW, auditAccessMW, (req, res) => res.json(queryAll('SELECT DISTINCT action FROM audit_log ORDER BY action')));
// Delete Log — datalogger deletions only (renamed from 'delete_datalogger' → 'Data Logger Deletion')
app.get('/api/delete-log', authMW, auditAccessMW, (req, res) => {
  const rows = queryAll(`SELECT * FROM audit_log WHERE action='delete_datalogger' ORDER BY id DESC LIMIT 500`);
  // Return with a display-friendly label
  res.json(rows.map(r => ({ ...r, action_label: 'Data Logger Deletion' })));
});

// =====================================================================
// 21 CFR POLICY INFO
// =====================================================================
app.get('/api/cfr/policy', authMW, (req, res) => res.json(CFR));

// GET /api/cfr/privileges — item 2: return privilege map for all roles
app.get('/api/cfr/privileges', authMW, (req, res) => res.json(ROLE_PRIVILEGES));

// GET /api/ntp — item 8: server UTC time for NTP-style sync check
app.get('/api/ntp', (req, res) => {
  res.json({
    server_utc:    ntpNow(),
    unix_ms:       Date.now(),
    timezone:      'UTC',
    note:          'Host should run ntpd/chronyd for hardware clock accuracy (21 CFR §11.10e)',
    drift_check:   'Compare server_utc with client time to detect drift > 1s'
  });
});

app.get('/api/cfr/setpoint-history/:deviceId/:paramId', authMW, (req, res) => {
  res.json(queryAll(
    'SELECT * FROM device_setpoints WHERE device_id=? AND param_id=? ORDER BY id DESC',
    [req.params.deviceId, req.params.paramId]
  ));
});

// =====================================================================
// HEALTH + DB VERIFY
// =====================================================================
app.get('/api/health', (req, res) => {
  let size=0; try { size=fs.existsSync(DB_FILE)?fs.statSync(DB_FILE).size:0; } catch {}
  res.json({ status:'ok', system:CFR.SYSTEM_NAME, version:CFR.SYSTEM_VERSION,
    regulation:CFR.REGULATION, uptime_s:Math.floor(process.uptime()),
    db_size_kb:(size/1024).toFixed(1),
    users:   queryOne('SELECT COUNT(*) as c FROM users')?.c||0,
    readings:queryOne('SELECT COUNT(*) as c FROM device_readings')?.c||0,
    audit_events:queryOne('SELECT COUNT(*) as c FROM audit_log')?.c||0 });
});

app.get('/api/db/verify', (req, res) => {
  let size=0; try { size=fs.existsSync(DB_FILE)?fs.statSync(DB_FILE).size:0; } catch {}
  res.json({
    total_readings: queryOne('SELECT COUNT(*) as c FROM device_readings')?.c||0,
    users:          queryOne('SELECT COUNT(*) as c FROM users')?.c||0,
    audit_events:   queryOne('SELECT COUNT(*) as c FROM audit_log')?.c||0,
    setpoint_changes: queryOne('SELECT COUNT(*) as c FROM device_setpoints')?.c||0,
    per_device:     queryAll('SELECT device_id, COUNT(*) as count FROM device_readings GROUP BY device_id'),
    last_5:         queryAll('SELECT device_id,timestamp,source_ip FROM device_readings ORDER BY id DESC LIMIT 5'),
    db_size_kb:     (size/1024).toFixed(1)
  });
});


// =====================================================================
// CRITICAL GAP 1: Concurrent session control — §11.10(d)
// Only ONE active session per user at a time
// =====================================================================
// Already enforced in authMW: when a new login succeeds, old session is deleted
// See login route — added below via patch

// =====================================================================
// CRITICAL GAP 2: Record Export Integrity — hash on every CSV/PDF export
// §11.10(c) — exported records must be verifiable
// =====================================================================
app.post('/api/export/audit', authMW, supervisorOnly, (req, res) => {
  const { from, to, action, limit = 5000 } = req.body || {};
  let sql = 'SELECT * FROM audit_log WHERE 1=1';
  const params = [];
  if (from)   { sql += ' AND timestamp >= ?'; params.push(from); }
  if (to)     { sql += ' AND timestamp <= ?'; params.push(to); }
  if (action) { sql += ' AND action = ?';     params.push(action); }
  sql += ' ORDER BY id ASC LIMIT ?'; params.push(limit);
  const rows = queryAll(sql, params);
  // Compute SHA-256 hash of the exported data for integrity verification
  const payload = JSON.stringify(rows);
  const exportHash = crypto.createHash('sha256').update(payload).digest('hex');
  const exportGuid = uuidv4();
  const exportTs   = ntpNow();
  // Log the export action in audit trail
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'audit_export', 'audit_log', 'ALL',
    `Audit trail exported: \${rows.length} records, hash: \${exportHash.slice(0,16)}…`,
    '', '', req.ip, `Export GUID: \${exportGuid}`);
  saveDB();
  res.json({
    export_guid:    exportGuid,
    exported_at:    exportTs,
    exported_by:    req.user.username,
    record_count:   rows.length,
    sha256_hash:    exportHash,
    hash_algorithm: 'SHA-256',
    cfr_note:       '21 CFR Part 11 §11.10(c) — verify this hash against database to confirm export integrity',
    records:        rows
  });
});

app.get('/api/export/verify/:hash', authMW, supervisorOnly, (req, res) => {
  const { hash } = req.params;
  const rows = queryAll('SELECT * FROM audit_log ORDER BY id ASC');
  const currentHash = crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex');
  res.json({
    provided_hash: hash,
    current_hash:  currentHash,
    match:         hash === currentHash,
    verified_at:   ntpNow(),
    record_count:  rows.length
  });
});

// =====================================================================
// CRITICAL GAP 3: Backup & Recovery endpoint
// =====================================================================
app.post('/api/backup/create', authMW, adminOnly, (req, res) => {
  try {
    const ts     = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const bkFile = path.join(__dirname, `backup_\${ts}.db`);
    const data   = db.export();
    const buf    = Buffer.from(data);
    fs.writeFileSync(bkFile, buf);
    const hash   = crypto.createHash('sha256').update(buf).digest('hex');
    // Write manifest alongside backup
    const manifest = {
      backup_guid:    uuidv4(),
      created_at:     ntpNow(),
      created_by:     req.user.username,
      filename:       path.basename(bkFile),
      size_bytes:     buf.length,
      sha256_hash:    hash,
      record_counts:  {
        audit_events: queryAll('SELECT COUNT(*) c FROM audit_log')[0].c,
        users:        queryAll('SELECT COUNT(*) c FROM users')[0].c,
        readings:     queryAll('SELECT COUNT(*) c FROM readings')[0].c,
      },
      cfr_note: '21 CFR Part 11 — validate this backup by restore-test before relying on it'
    };
    fs.writeFileSync(bkFile + '.manifest.json', JSON.stringify(manifest, null, 2));
    cfr_audit(req.user.username, req.user.name, req.user.role,
      'backup_created', 'system', path.basename(bkFile),
      `Database backup created: \${(buf.length/1024).toFixed(1)} KB, SHA-256: \${hash.slice(0,16)}…`,
      '', '', req.ip);
    saveDB();
    res.json({ ok: true, ...manifest });
  } catch(e) {
    res.status(500).json({ error: 'Backup failed: ' + e.message });
  }
});

app.get('/api/backup/list', authMW, adminOnly, (req, res) => {
  try {
    const files = fs.readdirSync(__dirname)
      .filter(f => f.startsWith('backup_') && f.endsWith('.db'))
      .map(f => {
        const manifest = path.join(__dirname, f + '.manifest.json');
        if (fs.existsSync(manifest)) return JSON.parse(fs.readFileSync(manifest, 'utf8'));
        const stat = fs.statSync(path.join(__dirname, f));
        return { filename: f, size_bytes: stat.size, created_at: stat.mtime.toISOString() };
      })
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    res.json(files);
  } catch(e) { res.json([]); }
});

app.post('/api/backup/verify/:filename', authMW, adminOnly, (req, res) => {
  const { filename } = req.params;
  const bkPath = path.join(__dirname, filename);
  if (!fs.existsSync(bkPath)) return res.status(404).json({ error: 'Backup file not found' });
  const buf  = fs.readFileSync(bkPath);
  const hash = crypto.createHash('sha256').update(buf).digest('hex');
  const manifestPath = bkPath + '.manifest.json';
  const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : null;
  const hashMatch = manifest ? manifest.sha256_hash === hash : null;
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'backup_verified', 'system', filename,
    `Backup integrity verified: hash \${hashMatch === null ? 'unchecked (no manifest)' : (hashMatch ? 'MATCH ✓' : 'MISMATCH ✗')}`,
    manifest?.sha256_hash || '', hash, req.ip);
  saveDB();
  res.json({ filename, sha256_hash: hash, manifest_hash: manifest?.sha256_hash, match: hashMatch, verified_at: ntpNow(), size_bytes: buf.length });
});

// =====================================================================
// CRITICAL GAP 4: Compliance Dashboard endpoint
// =====================================================================
app.get('/api/compliance/dashboard', authMW, adminOnly, (req, res) => {
  const users      = queryAll('SELECT id,username,role,enabled,is_locked,failed_attempts,last_login FROM users');
  const auditCount = queryAll('SELECT COUNT(*) c FROM audit_log')[0].c;
  const lastAudit  = queryAll('SELECT timestamp,action,username FROM audit_log ORDER BY id DESC LIMIT 1')[0];
  // Integrity check: verify last 100 records have non-empty checksums
  const badChecks  = queryAll(`SELECT COUNT(*) c FROM audit_log WHERE (checksum IS NULL OR checksum='') ORDER BY id DESC LIMIT 100`)[0].c;
  const backups    = (() => { try { return fs.readdirSync(__dirname).filter(f=>f.startsWith('backup_')&&f.endsWith('.db')); } catch(e){ return []; } })();
  const lastBackup = backups.sort().pop() || null;
  // Session count
  const activeSessions = queryAll('SELECT COUNT(*) c FROM sessions WHERE last_active > ?', [Date.now() - CFR.SESSION_TIMEOUT_MS])[0].c;
  const lockedUsers    = users.filter(u => u.is_locked);
  const disabledUsers  = users.filter(u => !u.enabled);
  res.json({
    generated_at:    ntpNow(),
    generated_by:    req.user.username,
    compliance_score: Math.round(((auditCount > 0 ? 1 : 0) + (badChecks === 0 ? 1 : 0) + (backups.length > 0 ? 1 : 0)) / 3 * 100),
    users: {
      total:          users.length,
      active_sessions: activeSessions,
      locked:         lockedUsers.map(u => ({ username: u.username, role: u.role, failed_attempts: u.failed_attempts })),
      disabled:       disabledUsers.map(u => ({ username: u.username, role: u.role })),
      all:            users.map(u => ({ ...u, password: undefined }))
    },
    audit_trail: {
      total_records:  auditCount,
      integrity_check: badChecks === 0 ? 'PASS — all sampled records have checksums' : `WARN — \${badChecks} records missing checksum`,
      last_entry:     lastAudit
    },
    backup: {
      count:          backups.length,
      last_backup:    lastBackup,
      status:         backups.length > 0 ? 'Backup exists — verify restore tested' : 'NO BACKUP — CRITICAL'
    },
    ntp: { server_utc: ntpNow(), note: 'Compare with /api/ntp for drift check' },
    password_policy: {
      min_length:    CFR.PASSWORD_MIN_LENGTH,
      expiry_days:   CFR.PASSWORD_EXPIRY_DAYS,
      history:       CFR.PASSWORD_HISTORY,
      max_attempts:  CFR.MAX_LOGIN_ATTEMPTS,
      lockout_min:   CFR.LOCKOUT_DURATION_MS / 60000
    },
    cfr_gaps: [
      { item: 'Predicate Rule Document', status: 'Manual — create formal mapping doc' },
      { item: 'Dual-Component E-Sig',    status: 'PIN column added — wire to UI for critical actions' },
      { item: 'Firmware Upgrade Log',    status: 'API available at POST /api/firmware/log' },
      { item: 'IEC 62443 / TLS 1.3',    status: 'Serve behind HTTPS reverse proxy (nginx/caddy)' },
      { item: 'HL7 / ASTM LIS API',     status: 'Stub at GET /api/lis/export' },
      { item: 'CMMS Integration',        status: 'Stub at GET /api/cmms/calibration' }
    ]
  });
});

// =====================================================================
// CRITICAL GAP 5: Incident / Deviation Log — GxP traceability
// =====================================================================
app.post('/api/incidents', authMW, (req, res) => {
  const { title, description, severity, device_id, audit_ref, assigned_to, due_date } = req.body || {};
  if (!title || !description || !severity)
    return res.status(400).json({ error: 'title, description, severity required' });
  const guid = uuidv4();
  run(`INSERT INTO incidents (guid,title,description,severity,device_id,audit_ref,assigned_to,due_date,reported_by,status,created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [guid, title, description, severity, device_id||'', audit_ref||'', assigned_to||'', due_date||'',
     req.user.username, 'OPEN', ntpNow()]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'create_incident', 'incident', guid,
    `Deviation reported: \${title} | Severity: \${severity}`, '', '', req.ip);
  saveDB();
  res.json({ ok: true, guid, title, severity, status: 'OPEN' });
});

app.get('/api/incidents', authMW, supervisorOnly, (req, res) => {
  res.json(queryAll('SELECT * FROM incidents ORDER BY created_at DESC'));
});

app.post('/api/incidents/:guid/close', authMW, supervisorOnly, (req, res) => {
  const { guid } = req.params;
  const { resolution } = req.body || {};
  if (!resolution) return res.status(400).json({ error: 'resolution text required' });
  run(`UPDATE incidents SET status='CLOSED', resolution=?, closed_by=?, closed_at=? WHERE guid=?`,
    [resolution, req.user.username, ntpNow(), guid]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'close_incident', 'incident', guid, `Incident closed: \${resolution.slice(0,80)}`, '', '', req.ip);
  saveDB();
  res.json({ ok: true });
});

// =====================================================================
// CRITICAL GAP 6: Alarm Escalation — multi-level with audit
// =====================================================================
app.post('/api/alarm-escalation/config', authMW, adminOnly, (req, res) => {
  const { device_id, param_id, primary_contact, secondary_contact, escalation_minutes } = req.body || {};
  if (!device_id || !primary_contact)
    return res.status(400).json({ error: 'device_id and primary_contact required' });
  run(`INSERT OR REPLACE INTO alarm_escalation (device_id,param_id,primary_contact,secondary_contact,escalation_minutes,created_by,created_at)
       VALUES (?,?,?,?,?,?,?)`,
    [device_id, param_id||'*', primary_contact, secondary_contact||'', escalation_minutes||15,
     req.user.username, ntpNow()]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'update_escalation_config', 'alarm_escalation', device_id,
    `Escalation config set: primary=\${primary_contact}, escalate after \${escalation_minutes||15}min`, '', '', req.ip);
  saveDB();
  res.json({ ok: true });
});

app.get('/api/alarm-escalation/config', authMW, supervisorOnly, (req, res) => {
  res.json(queryAll('SELECT * FROM alarm_escalation'));
});

// Alarm escalation check — call this from a cron/interval
function checkAlarmEscalation() {
  const unacked = queryAll(`SELECT a.*, ae.primary_contact, ae.secondary_contact, ae.escalation_minutes
    FROM alerts a LEFT JOIN alarm_escalation ae ON ae.device_id=a.device_id
    WHERE a.acknowledged=0`);
  unacked.forEach(alarm => {
    const age = (Date.now() - new Date(alarm.timestamp).getTime()) / 60000;
    if (alarm.escalation_minutes && age > alarm.escalation_minutes && !alarm.escalated) {
      run('UPDATE alerts SET escalated=1 WHERE id=?', [alarm.id]);
      cfr_audit('SYSTEM', 'Automated System', 'system',
        'alarm_escalated', 'alert', String(alarm.id),
        `Alarm #\${alarm.id} on \${alarm.device_id} escalated after \${Math.round(age)}min unacknowledged. Secondary: \${alarm.secondary_contact||'none'}`,
        '', '', '');
      saveDB();
      console.log(`[ESCALATION] Alarm #\${alarm.id} on \${alarm.device_id} → \${alarm.secondary_contact||'no secondary'}`);
    }
  });
}
setInterval(checkAlarmEscalation, 60 * 1000); // check every minute

// =====================================================================
// CRITICAL GAP 7: Dual-Component E-Sig for critical actions §11.200(a)
// =====================================================================
app.post('/api/esig/dual', authMW, (req, res) => {
  const { password, pin, action, target } = req.body || {};
  if (!password || !pin)
    return res.status(400).json({ error: 'Both password and PIN required for dual-component e-signature (21 CFR §11.200a)', code: 'DUAL_ESIG_REQUIRED' });
  const user = queryAll('SELECT * FROM users WHERE username=?', [req.user.username])[0];
  if (!user) return res.status(401).json({ error: 'User not found' });
  const pwOk  = bcrypt.compareSync(password, user.password);
  const pinOk = user.pin_hash ? bcrypt.compareSync(pin, user.pin_hash) : false;
  const guid  = uuidv4();
  if (!pwOk || !pinOk) {
    cfr_audit(req.user.username, req.user.name, req.user.role,
      'dual_esig_failed', target||'system', action||'unknown',
      `Dual e-signature FAILED: pw=\${pwOk?'OK':'FAIL'} pin=\${pinOk?'OK':'FAIL (not set)'}`,
      '', '', req.ip, '', '', 0, 'failed');
    saveDB();
    return res.status(401).json({ error: pwOk ? 'PIN invalid or not set. Use /api/users/set-pin first.' : 'Password invalid', code: 'DUAL_ESIG_FAILED', guid });
  }
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'dual_esig_verified', target||'system', action||'unknown',
    `Dual e-signature VERIFIED for: \${action} on \${target}`, '', '', req.ip, req.user.username, '', 1);
  saveDB();
  res.json({ ok: true, guid, verified_at: ntpNow(), signer: req.user.username, meaning: action, cfr_ref: '21 CFR Part 11 §11.200(a)(1)' });
});

app.post('/api/users/set-pin', authMW, (req, res) => {
  const { password, pin } = req.body || {};
  if (!password || !pin) return res.status(400).json({ error: 'password and pin required' });
  if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 4-8 digits' });
  const user = queryAll('SELECT * FROM users WHERE id=?', [req.user.id])[0];
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Password invalid' });
  const pinHash = bcrypt.hashSync(pin, 10);
  run('UPDATE users SET pin_hash=? WHERE id=?', [pinHash, req.user.id]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'set_pin', 'user', req.user.username, 'User set dual e-signature PIN (21 CFR §11.200a)', '', '', req.ip);
  saveDB();
  res.json({ ok: true, message: 'PIN set — dual e-signature now available' });
});

// =====================================================================
// CRITICAL GAP 8: Firmware Upgrade Audit Log — synchronized with STM32
// =====================================================================
app.post('/api/firmware/log', authMW, supervisorOnly, (req, res) => {
  const { device_id, device_serial, old_version, new_version, method } = req.body || {};
  if (!device_id || !new_version)
    return res.status(400).json({ error: 'device_id and new_version required' });
  const guid = uuidv4();
  run(`INSERT INTO firmware_log (guid,device_id,device_serial,old_version,new_version,method,applied_by,applied_at)
       VALUES (?,?,?,?,?,?,?,?)`,
    [guid, device_id, device_serial||'', old_version||'unknown', new_version,
     method||'manual', req.user.username, ntpNow()]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'firmware_upgrade', 'device', device_id,
    `Firmware updated: \${old_version||'?'} → \${new_version} | Serial: \${device_serial||'N/A'} | Method: \${method||'manual'}`,
    old_version||'', new_version, req.ip, `Firmware GUID: \${guid}`, req.user.username, 1);
  saveDB();
  res.json({ ok: true, guid, device_id, old_version, new_version, applied_at: ntpNow(), applied_by: req.user.username });
});

app.get('/api/firmware/log', authMW, supervisorOnly, (req, res) => {
  const { device_id } = req.query;
  const sql    = device_id ? 'SELECT * FROM firmware_log WHERE device_id=? ORDER BY applied_at DESC' : 'SELECT * FROM firmware_log ORDER BY applied_at DESC';
  const params = device_id ? [device_id] : [];
  res.json(queryAll(sql, params));
});

// =====================================================================
// DATA LOGGER — experiment/batch recording sessions (Trend Graphs tab)
// Each "logger" is a named recording run against one device. Points are
// snapshotted from device_readings on a timer (handled client-side or by
// the /api/datalogger/:id/capture tick below) so the dataset is fully
// independent of the rolling device_readings history.
// =====================================================================
app.post('/api/datalogger', authMW, operatorOnly, (req, res) => {
  const { name, device_id, param_ids, interval_sec, notes } = req.body || {};
  if (!name || !device_id) return res.status(400).json({ error:'name and device_id required' });
  const device = queryOne('SELECT * FROM devices WHERE id=? AND enabled=1', [device_id]);
  if (!device) return res.status(404).json({ error:'Device not found' });

  const guid = uuidv4();
  run(`INSERT INTO data_logger (guid,name,device_id,param_ids,interval_sec,status,started_by,started_at,notes)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    [guid, name.trim(), device_id, JSON.stringify(param_ids||[]), interval_sec||5, 'RUNNING',
     req.user.username, ntpNow(), notes||'']);
  const row = queryOne('SELECT id FROM data_logger WHERE guid=?', [guid]);

  cfr_audit(req.user.username, req.user.name, req.user.role,
    'create_datalogger', 'data_logger', guid,
    `Data logger started: "${name.trim()}" on device ${device_id}`, '', '', req.ip);
  saveDB();
  res.status(201).json({ ok:true, id:row.id, guid, name:name.trim(), device_id, status:'RUNNING' });
});

app.get('/api/datalogger', authMW, operatorOnly, (req, res) => {
  // Hide soft-deleted entries from the normal list
  res.json(queryAll('SELECT *, (SELECT COUNT(*) FROM data_logger_points WHERE logger_id=data_logger.id) as point_count FROM data_logger WHERE deleted=0 ORDER BY id DESC'));
});

app.get('/api/datalogger/:id', authMW, operatorOnly, (req, res) => {
  const logger = queryOne('SELECT * FROM data_logger WHERE id=? AND deleted=0', [req.params.id]);
  if (!logger) return res.status(404).json({ error:'Logger not found' });
  const points = queryAll('SELECT * FROM data_logger_points WHERE logger_id=? ORDER BY id ASC LIMIT 5000', [req.params.id]);
  res.json({ ...logger, points: points.map(p => ({ timestamp:p.timestamp, ...JSON.parse(p.payload) })) });
});

// Capture one snapshot — called on a client-side interval timer while the
// logger is RUNNING, or could be wired to a server setInterval per logger.
app.post('/api/datalogger/:id/capture', authMW, operatorOnly, (req, res) => {
  const logger = queryOne('SELECT * FROM data_logger WHERE id=? AND deleted=0', [req.params.id]);
  if (!logger) return res.status(404).json({ error:'Logger not found' });
  if (logger.status !== 'RUNNING') return res.status(400).json({ error:'Logger is not running' });

  const latest = queryOne('SELECT payload,timestamp FROM device_readings WHERE device_id=? ORDER BY id DESC LIMIT 1', [logger.device_id]);
  if (!latest) return res.status(404).json({ error:'No sensor data available yet for this device' });

  run('INSERT INTO data_logger_points (logger_id,payload) VALUES (?,?)', [logger.id, latest.payload]);
  saveDB();
  res.json({ ok:true, captured_at: ntpNow() });
});

app.post('/api/datalogger/:id/stop', authMW, operatorOnly, (req, res) => {
  const logger = queryOne('SELECT * FROM data_logger WHERE id=? AND deleted=0', [req.params.id]);
  if (!logger) return res.status(404).json({ error:'Logger not found' });
  run(`UPDATE data_logger SET status='STOPPED', stopped_by=?, stopped_at=? WHERE id=?`,
    [req.user.username, ntpNow(), logger.id]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'stop_datalogger', 'data_logger', logger.guid,
    `Data logger stopped: "${logger.name}"`, 'RUNNING', 'STOPPED', req.ip);
  saveDB();
  res.json({ ok:true });
});

// DELETE — admin/factory only, requires reason, fully audited.
// Soft-delete: row + its captured points are flagged, not removed, so the
// "delete log" entry in the audit trail can always be cross-referenced
// back to what was deleted (21 CFR §11.10c — record integrity).
app.delete('/api/datalogger/:id', authMW, factoryOnly, (req, res) => {
  const { reason } = req.body || {};
  const logger = queryOne('SELECT * FROM data_logger WHERE id=? AND deleted=0', [req.params.id]);
  if (!logger) return res.status(404).json({ error:'Logger not found or already deleted' });
  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error:'Reason for deletion required (min 5 characters) — 21 CFR Part 11', code:'REASON_REQUIRED' });

  const pointCount = queryOne('SELECT COUNT(*) c FROM data_logger_points WHERE logger_id=?', [logger.id]).c;

  run(`UPDATE data_logger SET deleted=1, deleted_by=?, deleted_at=?, delete_reason=?, status='DELETED' WHERE id=?`,
    [req.user.username, ntpNow(), reason.trim(), logger.id]);

  cfr_audit(req.user.username, req.user.name, req.user.role,
    'delete_datalogger', 'data_logger', logger.guid,
    `Data logger DELETED: "${logger.name}" on ${logger.device_id} (${pointCount} captured points) — reason: ${reason.trim()}`,
    JSON.stringify({ name:logger.name, device_id:logger.device_id, point_count:pointCount, status:logger.status }),
    JSON.stringify({ deleted:true }),
    req.ip, reason.trim());
  saveDB();
  res.json({ ok:true, message:`Data logger "${logger.name}" deleted (${pointCount} points retained for audit)` });
});

// ── Machine ON/OFF toggle — 21 CFR §11.10e audit trail ──────────────────
// Called from the ON/OFF buttons on instrument cards. Records state change
// with timestamp, user, reason, and device context in the audit trail.
app.post('/api/device/:deviceId/toggle', authMW, operatorOnly, (req, res) => {
  const { deviceId } = req.params;
  const { param_id, param_label, value, reason } = req.body || {};
  if (param_id === undefined || value === undefined)
    return res.status(400).json({ error: 'param_id and value required' });
  const displayVal = value ? 'ON' : 'OFF';
  const oldVal     = !value ? 'ON' : 'OFF';  // inverse of new
  cfr_audit(
    req.user.username, req.user.name, req.user.role,
    'machine_toggle', 'device', deviceId,
    `${param_label || param_id} set ${displayVal} on ${deviceId}`,
    oldVal, displayVal, req.ip,
    reason || `Operator set ${param_label || param_id} ${displayVal}`
  );
  saveDB();
  res.json({ ok: true, device_id: deviceId, param_id, value, recorded_at: ntpNow() });
});

// ── GET dedicated "delete log" — every datalogger AND user deletion in one
// filtered view, for quick compliance review without scrolling full audit.
// delete-log is now served by the auditAccessMW route above

// =====================================================================
// CRITICAL GAP 9: IEC 62443 / TLS note + security headers
// =====================================================================
// TLS 1.3: run behind nginx/caddy with TLS termination
// Security headers added here for defense-in-depth
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  next();
});

// =====================================================================
// CRITICAL GAP 10: HL7/ASTM LIS Export stub
// =====================================================================
app.get('/api/lis/export', authMW, supervisorOnly, (req, res) => {
  const { device_id, from, to } = req.query;
  let sql = 'SELECT * FROM readings WHERE 1=1';
  const params = [];
  if (device_id) { sql += ' AND device_id=?'; params.push(device_id); }
  if (from)      { sql += ' AND timestamp>=?'; params.push(from); }
  if (to)        { sql += ' AND timestamp<=?'; params.push(to); }
  sql += ' ORDER BY timestamp ASC LIMIT 1000'; 
  const rows = queryAll(sql, params);
  const hash = crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex');
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'lis_export', 'readings', device_id||'ALL',
    `LIS export: \${rows.length} readings, SHA-256: \${hash.slice(0,16)}…`, '', '', req.ip);
  saveDB();
  // HL7 v2.5 ORU^R01-style wrapper (simplified)
  res.json({
    message_type:   'ORU^R01',
    hl7_version:    '2.5',
    export_guid:    uuidv4(),
    exported_at:    ntpNow(),
    exported_by:    req.user.username,
    sha256_hash:    hash,
    record_count:   rows.length,
    device_filter:  device_id || 'ALL',
    observations:   rows.map(r => ({
      obx_type: 'NM',
      device_id: r.device_id,
      timestamp: r.timestamp,
      data:      r.data ? JSON.parse(r.data) : {}
    })),
    cfr_note: '21 CFR Part 11 §11.10(b) — records accurate and complete for LIS integration'
  });
});

// =====================================================================
// CRITICAL GAP 11: CMMS Integration — calibration, service, alarms
// =====================================================================
app.get('/api/cmms/calibration', authMW, supervisorOnly, (req, res) => {
  const devices = queryAll('SELECT * FROM devices');
  res.json({
    exported_at:  ntpNow(),
    sha256_hash:  crypto.createHash('sha256').update(JSON.stringify(devices)).digest('hex'),
    instruments:  devices.map(d => ({
      instrument_id:    d.id,
      name:             d.name,
      ip:               d.ip,
      type:             d.type,
      last_reading:     d.last_seen,
      calibration_due:  'See instrument manual — integrate with CMMS for due-date tracking',
      service_history:  `GET /api/firmware/log?device_id=\${d.id}`,
      alarm_history:    `GET /api/alerts?device_id=\${d.id}`
    }))
  });
});

app.get('/api/cmms/service-history', authMW, supervisorOnly, (req, res) => {
  const { device_id } = req.query;
  const fw    = queryAll(device_id ? 'SELECT * FROM firmware_log WHERE device_id=? ORDER BY applied_at DESC' : 'SELECT * FROM firmware_log ORDER BY applied_at DESC', device_id ? [device_id] : []);
  const alarms = queryAll(device_id ? 'SELECT * FROM alerts WHERE device_id=? ORDER BY timestamp DESC LIMIT 100' : 'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100', device_id ? [device_id] : []);
  res.json({
    exported_at:    ntpNow(),
    device_filter:  device_id || 'ALL',
    firmware_log:   fw,
    alarm_history:  alarms
  });
});

// =====================================================================
// AUTO DATA LOGGER — server-side, no browser required
// Every LOG_INTERVAL_MS all enabled devices are snapshotted into the
// auto_log table. A separate "session" (named record) can be created
// by any operator via the UI to mark experiment start/stop timestamps.
// =====================================================================
const LOG_INTERVAL_MS  = 5 * 60 * 1000;  // 5 minutes — edit here if needed
const LOG_INTERVAL_SEC = LOG_INTERVAL_MS / 1000;

// Ensure the auto_log tables exist (idempotent — safe to run each boot)
function ensureAutoLogTables() {
  // Add is_protected column to users table if it doesn't exist (existing DBs)
  try { db.run(`ALTER TABLE users ADD COLUMN is_protected INTEGER NOT NULL DEFAULT 0`); } catch(e) {}
  // Add audit_access column to users table if it doesn't exist (existing DBs)
  try { db.run(`ALTER TABLE users ADD COLUMN audit_access INTEGER NOT NULL DEFAULT 0`); } catch(e) {}
  // Add is_active column to profiles table if it doesn't exist (existing DBs)
  try { db.run(`ALTER TABLE profiles ADD COLUMN is_active INTEGER NOT NULL DEFAULT 0`); } catch(e) {}
  // Ensure factory account is always protected
  db.run(`UPDATE users SET is_protected=1 WHERE username='factory'`);
  db.run(`UPDATE users SET audit_access=1 WHERE role IN ('administrator','factory')`);
  db.run(`CREATE TABLE IF NOT EXISTS auto_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    payload     TEXT NOT NULL,
    source      TEXT DEFAULT 'auto'
  )`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_auto_log_dev
    ON auto_log(device_id, timestamp DESC)`);
  db.run(`CREATE TABLE IF NOT EXISTS log_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    guid        TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    started_by  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    stopped_by  TEXT DEFAULT '',
    stopped_at  TEXT DEFAULT '',
    status      TEXT DEFAULT 'RUNNING',
    deleted     INTEGER DEFAULT 0,
    deleted_by  TEXT DEFAULT '',
    deleted_at  TEXT DEFAULT '',
    delete_reason TEXT DEFAULT ''
  )`);
  dbDirty = true;
}

// Core capture — called by the auto-timer every 5 minutes
function captureAllDevices() {
  const devices = queryAll('SELECT id FROM devices WHERE enabled=1');
  let count = 0;
  devices.forEach(d => {
    const latest = queryOne(
      'SELECT payload,timestamp FROM device_readings WHERE device_id=? ORDER BY id DESC LIMIT 1',
      [d.id]
    );
    if (!latest) return;
    run('INSERT INTO auto_log (timestamp,device_id,payload,source) VALUES (?,?,?,?)',
      [ntpNow(), d.id, latest.payload, 'auto']);
    count++;
  });
  if (count > 0) {
    dbDirty = true;
    saveDB();
    console.log(`[AUTO-LOG] ${new Date().toISOString().slice(0,19)} — captured ${count} device(s)`);
  }
}

// ── Auto-log routes ──────────────────────────────────────────────────

// GET all auto-logged data, optionally filtered by device/time
app.get('/api/autolog', authMW, operatorOnly, (req, res) => {
  const { device_id, from, to, limit = 500, offset = 0 } = req.query;
  let sql = 'SELECT * FROM auto_log WHERE 1=1', p = [];
  if (device_id) { sql += ' AND device_id=?'; p.push(device_id); }
  if (from)      { sql += ' AND timestamp>=?'; p.push(from); }
  if (to)        { sql += ' AND timestamp<=?'; p.push(to); }
  const total = queryOne(sql.replace('SELECT *','SELECT COUNT(*) c'), p)?.c || 0;
  sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
  p.push(Math.min(Number(limit), 2000), Number(offset));
  const rows = queryAll(sql, p);
  // Expand payload JSON into flat rows for easy display
  const expanded = rows.map(r => ({
    id:        r.id,
    timestamp: r.timestamp,
    device_id: r.device_id,
    source:    r.source,
    ...JSON.parse(r.payload)
  }));
  res.json({ total, limit: Number(limit), offset: Number(offset), interval_sec: LOG_INTERVAL_SEC, rows: expanded });
});

// GET latest reading per device — summary view
app.get('/api/autolog/latest', authMW, operatorOnly, (req, res) => {
  const devices = queryAll('SELECT id,name FROM devices WHERE enabled=1');
  const result = devices.map(d => {
    const latest = queryOne(
      'SELECT * FROM auto_log WHERE device_id=? ORDER BY id DESC LIMIT 1', [d.id]
    );
    if (!latest) return { device_id: d.id, name: d.name, last_logged: null };
    return {
      device_id:   d.id,
      name:        d.name,
      last_logged: latest.timestamp,
      ...JSON.parse(latest.payload)
    };
  });
  res.json({ captured_at: ntpNow(), interval_sec: LOG_INTERVAL_SEC, devices: result });
});

// GET stats — total rows, per-device counts, oldest/newest timestamps
app.get('/api/autolog/stats', authMW, operatorOnly, (req, res) => {
  const total   = queryOne('SELECT COUNT(*) c FROM auto_log')?.c || 0;
  const perDev  = queryAll('SELECT device_id, COUNT(*) as count, MIN(timestamp) as oldest, MAX(timestamp) as newest FROM auto_log GROUP BY device_id');
  res.json({ total, interval_sec: LOG_INTERVAL_SEC, per_device: perDev, server_time: ntpNow() });
});

// GET export — full CSV-ready dump for a device over a time range
app.get('/api/autolog/export', authMW, operatorOnly, (req, res) => {
  const { device_id, from, to } = req.query;
  let sql = 'SELECT * FROM auto_log WHERE 1=1', p = [];
  if (device_id) { sql += ' AND device_id=?'; p.push(device_id); }
  if (from)      { sql += ' AND timestamp>=?'; p.push(from); }
  if (to)        { sql += ' AND timestamp<=?'; p.push(to); }
  sql += ' ORDER BY id ASC LIMIT 50000';
  const rows = queryAll(sql, p);
  cfr_audit('SYSTEM', 'SYSTEM', 'system', 'autolog_export', 'auto_log',
    device_id || 'ALL', `Auto-log exported: ${rows.length} records for ${device_id||'ALL'} devices`);
  saveDB();
  res.json({
    exported_at:  ntpNow(),
    device_filter: device_id || 'ALL',
    interval_sec: LOG_INTERVAL_SEC,
    record_count: rows.length,
    rows: rows.map(r => ({ id:r.id, timestamp:r.timestamp, device_id:r.device_id, ...JSON.parse(r.payload) }))
  });
});

// DELETE a range of auto-log entries — factory/admin only, requires reason
app.delete('/api/autolog', authMW, factoryOnly, (req, res) => {
  const { device_id, from, to, reason } = req.body || {};
  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error: 'Reason required (min 5 characters)', code: 'REASON_REQUIRED' });
  let sql = 'SELECT COUNT(*) c FROM auto_log WHERE 1=1', p = [];
  if (device_id) { sql += ' AND device_id=?'; p.push(device_id); }
  if (from)      { sql += ' AND timestamp>=?'; p.push(from); }
  if (to)        { sql += ' AND timestamp<=?'; p.push(to); }
  const count = queryOne(sql, p)?.c || 0;
  let delSql = 'DELETE FROM auto_log WHERE 1=1', dp = [];
  if (device_id) { delSql += ' AND device_id=?'; dp.push(device_id); }
  if (from)      { delSql += ' AND timestamp>=?'; dp.push(from); }
  if (to)        { delSql += ' AND timestamp<=?'; dp.push(to); }
  run(delSql, dp);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'delete_autolog', 'auto_log', device_id || 'ALL',
    `Auto-log entries deleted: ${count} records for ${device_id||'ALL'} — reason: ${reason.trim()}`,
    JSON.stringify({ device_id, from, to, count }), '{}', req.ip, reason.trim());
  saveDB();
  res.json({ ok: true, deleted_count: count });
});

// ── Named Log Sessions (optional experiment markers) ─────────────────

app.post('/api/log-sessions', authMW, operatorOnly, (req, res) => {
  const { name, description } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const guid = uuidv4();
  run(`INSERT INTO log_sessions (guid,name,description,started_by,started_at) VALUES (?,?,?,?,?)`,
    [guid, name.trim(), description || '', req.user.username, ntpNow()]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'create_log_session', 'log_sessions', guid, `Log session started: "${name.trim()}"`, '', '', req.ip);
  saveDB();
  res.status(201).json({ ok: true, guid });
});

app.get('/api/log-sessions', authMW, operatorOnly, (req, res) => {
  res.json(queryAll('SELECT * FROM log_sessions WHERE deleted=0 ORDER BY id DESC'));
});

app.post('/api/log-sessions/:guid/stop', authMW, operatorOnly, (req, res) => {
  run(`UPDATE log_sessions SET status='STOPPED',stopped_by=?,stopped_at=? WHERE guid=?`,
    [req.user.username, ntpNow(), req.params.guid]);
  saveDB();
  res.json({ ok: true });
});

app.delete('/api/log-sessions/:guid', authMW, factoryOnly, (req, res) => {
  const { reason } = req.body || {};
  if (!reason || reason.trim().length < 5)
    return res.status(400).json({ error: 'Reason required (min 5 characters)' });
  const sess = queryOne('SELECT * FROM log_sessions WHERE guid=?', [req.params.guid]);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  run(`UPDATE log_sessions SET deleted=1,deleted_by=?,deleted_at=?,delete_reason=? WHERE guid=?`,
    [req.user.username, ntpNow(), reason.trim(), req.params.guid]);
  cfr_audit(req.user.username, req.user.name, req.user.role,
    'delete_log_session', 'log_sessions', req.params.guid,
    `Log session deleted: "${sess.name}" — reason: ${reason.trim()}`, '', '', req.ip, reason.trim());
  saveDB();
  res.json({ ok: true });
});


initDB().then(() => {
  // Ensure auto-log tables exist (added after initial schema — safe to re-run)
  ensureAutoLogTables();

  // ── Server-side Auto Data Logger — all devices every 5 minutes ──
  // No browser required — runs on the Node.js process continuously.
  setTimeout(() => {
    captureAllDevices();                              // immediate first capture
    setInterval(captureAllDevices, LOG_INTERVAL_MS);  // then every 5 minutes
    console.log(`[AUTO-LOG] Started — capturing all devices every ${LOG_INTERVAL_SEC / 60} min`);
  }, 3000); // 3s delay so ingest routes are ready

  const devs = queryAll('SELECT id,name FROM devices');
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n${'═'.repeat(62)}`);
    console.log(`  NucleoSense  —  ${CFR.REGULATION} Compliant`);
    console.log(`  http://localhost:${PORT}`);
    console.log(`${'═'.repeat(62)}`);
    console.log(`  Users (from database):`);
    console.log(`    admin      / Admin@123  (administrator)`);
    console.log(`    operator   / Oper@456   (operator)`);
    console.log(`    qa_officer / QA@user789 (qa)`);
    console.log(`\n  Policy:`);
    console.log(`    Session timeout : ${CFR.SESSION_TIMEOUT_MS/60000} min`);
    console.log(`    Password expiry : ${CFR.PASSWORD_EXPIRY_DAYS} days`);
    console.log(`    Lockout after   : ${CFR.MAX_LOGIN_ATTEMPTS} failed attempts`);
    console.log(`    E-Signature     : Required for all setpoint changes`);
    console.log(`    Reason for change: Required for all setpoint changes`);
    console.log(`\n  STM32 endpoints:`);
    devs.forEach(d => console.log(`    POST /api/device/${d.id}/ingest`));
    console.log(`  DB verify:   http://localhost:${PORT}/api/db/verify`);
    console.log(`  NTP check:   http://localhost:${PORT}/api/ntp`);
    console.log(`  Privileges:  http://localhost:${PORT}/api/cfr/privileges`);
    console.log(`  Compliance:  http://localhost:${PORT}/api/compliance/dashboard`);
    console.log(`  Incidents:   http://localhost:${PORT}/api/incidents`);
    console.log(`  Firmware:    http://localhost:${PORT}/api/firmware/log`);
    console.log(`  LIS Export:  http://localhost:${PORT}/api/lis/export`);
    console.log(`  CMMS:        http://localhost:${PORT}/api/cmms/calibration`);
    console.log(`  Backup:      http://localhost:${PORT}/api/backup/create`);
    console.log(`\n  [NTP] Ensure host runs ntpd/chronyd for 21 CFR §11.10e timestamp accuracy`);
    console.log(`${'═'.repeat(62)}\n`);
  });
}).catch(e => { console.error('[FATAL]', e); process.exit(1); });