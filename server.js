const express = require('express');
const session = require('express-session');
const ldap    = require('ldapjs');
const multer  = require('multer');
const xlsx    = require('xlsx');
const pdfParse = require('pdf-parse');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const { initDB, all, get, run, save } = require('./database');

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const app  = express();
const PORT = process.env.PORT || 6122;

// ── AD Config ───────────────────────────────────────────────────────────────
const AD_URL    = process.env.AD_URL    || 'ldap://10.17.113.136';
const AD_SUFFIX = process.env.AD_SUFFIX || 'dc=bcw-intern,dc=local';
const AD_DOMAIN = process.env.AD_DOMAIN || 'BCW-INTERN';

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ limit: '30mb', extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'reinigung-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));
app.use('/uploads', (req, res, next) => {
  if (req.session && req.session.user) return next();
  return res.status(401).send('Nicht authentifiziert');
}, express.static(UPLOADS_DIR));

// ── Multer Storage ──────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
      const stamp = Date.now() + '_' + crypto.randomBytes(4).toString('hex');
      cb(null, stamp + '_' + safe);
    }
  }),
  limits: { fileSize: 30 * 1024 * 1024 }
});

// ── Helpers ─────────────────────────────────────────────────────────────────
function nowISO() { return new Date().toISOString(); }
function userName(req)  { return (req.session?.user?.displayName) || 'System'; }
function userLogin(req) { return (req.session?.user?.sAMAccountName) || 'system'; }
function userRolle(req) { return (req.session?.user?.rolle) || 'Lesezugriff'; }
function userStandort(req) {
  if (!req.session || !req.session.user) return 'Alle';
  if (req.session.user.rolle === 'Super-Admin') return 'Alle';
  return req.session.user.standort;
}
function audit(aktion, objektId, benutzer, details) {
  run('INSERT INTO audit_log (zeitstempel,aktion,objekt_id,benutzer,details) VALUES (?,?,?,?,?)',
      nowISO(), aktion, objektId || '', benutzer || '', details || '');
}
function hatBerechtigung(rolle, bereich, aktion = 'lesen') {
  const perm = get('SELECT * FROM berechtigungen WHERE rolle = ? AND bereich = ?', rolle, bereich);
  if (!perm) return rolle === 'Super-Admin';
  if (aktion === 'lesen')     return perm.lesen === 1;
  if (aktion === 'schreiben') return perm.schreiben === 1;
  if (aktion === 'loeschen')  return perm.loeschen === 1;
  return false;
}
function requirePerm(bereich, aktion = 'lesen') {
  return (req, res, next) => {
    if (!hatBerechtigung(userRolle(req), bereich, aktion)) {
      return res.status(403).json({ error: `Keine Berechtigung für ${bereich} (${aktion})` });
    }
    next();
  };
}

// ── LDAP Auth ───────────────────────────────────────────────────────────────
function ldapAuth(username, password) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, val) => { if (!settled) { settled = true; fn(val); } };
    const client = ldap.createClient({ url: AD_URL, connectTimeout: 5000, tlsOptions: { rejectUnauthorized: false } });
    const bindDN = `${username}@${AD_DOMAIN}`;
    client.on('error', (err) => { try { client.destroy(); } catch(_){} finish(reject, err); });
    client.on('connectTimeout', () => { try { client.destroy(); } catch(_){} finish(reject, new Error('LDAP Timeout')); });
    client.bind(bindDN, password, (err) => {
      if (err) { try { client.destroy(); } catch(_){} return finish(reject, err); }
      const opts = { filter: `(sAMAccountName=${username})`, scope: 'sub', attributes: ['sAMAccountName','displayName','mail','department'] };
      client.search(AD_SUFFIX, opts, (err, sr) => {
        if (err) { try { client.destroy(); } catch(_){} return finish(reject, err); }
        let info = null;
        sr.on('searchEntry', (entry) => {
          const attrs = {};
          if (entry.pojo?.attributes) for (const a of entry.pojo.attributes) attrs[a.type] = a.values.length === 1 ? a.values[0] : a.values;
          info = {
            sAMAccountName: attrs.sAMAccountName || username,
            displayName:    attrs.displayName    || username,
            mail:           attrs.mail           || '',
            department:     attrs.department     || ''
          };
        });
        sr.on('end', () => { try { client.destroy(); } catch(_){} finish(resolve, info || { sAMAccountName: username, displayName: username, mail: '', department: '' }); });
        sr.on('error', (e) => { try { client.destroy(); } catch(_){} finish(reject, e); });
      });
    });
  });
}
function ldapSearch(query, creds) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, val) => { if (!settled) { settled = true; fn(val); } };
    const client = ldap.createClient({ url: AD_URL, connectTimeout: 5000, tlsOptions: { rejectUnauthorized: false } });
    client.on('error', (err) => { try { client.destroy(); } catch(_){} finish(reject, err); });
    client.bind(`${creds.username}@${AD_DOMAIN}`, creds.password, (be) => {
      if (be) { try { client.destroy(); } catch(_){} return finish(reject, be); }
      const filter = query.includes('.')
        ? `(|(sAMAccountName=${query})(mail=${query}*)(displayName=*${query}*))`
        : `(|(sAMAccountName=*${query}*)(displayName=*${query}*)(givenName=*${query}*)(sn=*${query}*))`;
      const opts = { filter, scope: 'sub', attributes: ['sAMAccountName','displayName','givenName','sn','mail','department'], sizeLimit: 15 };
      client.search(AD_SUFFIX, opts, (err, sr) => {
        if (err) { try { client.destroy(); } catch(_){} return finish(reject, err); }
        const users = [];
        sr.on('searchEntry', (entry) => {
          const attrs = {};
          if (entry.pojo?.attributes) for (const a of entry.pojo.attributes) attrs[a.type] = a.values.length === 1 ? a.values[0] : a.values;
          if (attrs.sAMAccountName) users.push({
            sAMAccountName: attrs.sAMAccountName,
            displayName: attrs.displayName || '',
            givenName: attrs.givenName || '',
            sn: attrs.sn || '',
            mail: attrs.mail || '',
            department: attrs.department || ''
          });
        });
        sr.on('end', () => { try { client.destroy(); } catch(_){} finish(resolve, users); });
        sr.on('error', (e) => { try { client.destroy(); } catch(_){} finish(reject, e); });
      });
    });
  });
}

// ── Login Rate Limit ────────────────────────────────────────────────────────
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5, WINDOW_MS = 15 * 60 * 1000, BLOCK_MS = 15 * 60 * 1000;
function checkLoginRate(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (entry?.blockedUntil > now) return res.status(429).json({ error: `Zu viele Versuche. ${Math.ceil((entry.blockedUntil-now)/1000)}s warten.` });
  if (entry && now - entry.firstAt > WINDOW_MS) loginAttempts.delete(ip);
  next();
}
function recordLoginFailure(req) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  let e = loginAttempts.get(ip) || { count: 0, firstAt: now, blockedUntil: 0 };
  e.count++;
  if (e.count >= MAX_ATTEMPTS) e.blockedUntil = now + BLOCK_MS;
  loginAttempts.set(ip, e);
}

// ── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/login', checkLoginRate, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
  try {
    const info = await ldapAuth(username, password);
    const dbUser = get('SELECT * FROM benutzer WHERE LOWER(ad_user) = LOWER(?) AND aktiv = 1', username);
    if (!dbUser) {
      recordLoginFailure(req);
      return res.status(403).json({ error: 'Kein Zugang. AD-Konto nicht freigeschaltet.' });
    }
    info.rolle = dbUser.rolle;
    info.standort = dbUser.standort;
    info.dbId = dbUser.id;
    req.session.user = info;
    req.session.adCreds = { username, password };
    run('UPDATE benutzer SET letzter_login = ? WHERE id = ?', nowISO(), dbUser.id);
    audit('LOGIN', '', info.displayName, `AD-Login: ${info.sAMAccountName} (${dbUser.rolle})`);
    save();
    loginAttempts.delete(req.ip);
    res.json({ success: true, user: info });
  } catch (err) {
    console.error('LDAP auth failed:', err.message);
    recordLoginFailure(req);
    res.status(401).json({ error: 'Anmeldung fehlgeschlagen.' });
  }
});
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});
app.get('/api/me', (req, res) => {
  if (req.session?.user) res.json(req.session.user);
  else res.status(401).json({ error: 'Nicht angemeldet' });
});

// ── Auth-Guard ──────────────────────────────────────────────────────────────
app.use('/api', (req, res, next) => {
  if (['/login', '/logout', '/me'].includes(req.path)) return next();
  if (req.session?.user) return next();
  res.status(401).json({ error: 'Nicht authentifiziert' });
});

// ── Berechtigungen-Helper für Frontend ──────────────────────────────────────
app.get('/api/berechtigungen-eigene', (req, res) => {
  const rolle = userRolle(req);
  const rows = all('SELECT bereich, lesen, schreiben, loeschen FROM berechtigungen WHERE rolle = ?', rolle);
  res.json({ rolle, berechtigungen: rows });
});

// ════════════════════════════════════════════════════════════════════════════
//  STANDORTE
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/standorte', requirePerm('standorte','lesen'), (req, res) => {
  res.json(all('SELECT * FROM standorte ORDER BY name'));
});
app.post('/api/standorte', requirePerm('standorte','schreiben'), (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name fehlt' });
  try {
    run('INSERT INTO standorte (name) VALUES (?)', name);
    audit('STANDORT_NEU', '', userName(req), `Standort angelegt: ${name}`);
    save();
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: 'Standort existiert bereits' }); }
});
app.put('/api/standorte/:name', requirePerm('standorte','schreiben'), (req, res) => {
  const { name } = req.params;
  const { newName } = req.body;
  if (!newName) return res.status(400).json({ error: 'Neuer Name fehlt' });
  run('UPDATE standorte SET name = ? WHERE name = ?', newName, name);
  // Cascade in anderen Tabellen
  run('UPDATE leistungsverzeichnisse SET standort = ? WHERE standort = ?', newName, name);
  run('UPDATE reinigungsaufgaben    SET standort = ? WHERE standort = ?', newName, name);
  run('UPDATE protokolle            SET standort = ? WHERE standort = ?', newName, name);
  run('UPDATE benutzer              SET standort = ? WHERE standort = ?', newName, name);
  audit('STANDORT_EDIT', '', userName(req), `${name} → ${newName}`);
  save();
  res.json({ success: true });
});
app.delete('/api/standorte/:name', requirePerm('standorte','loeschen'), (req, res) => {
  const { name } = req.params;
  const used = get('SELECT COUNT(*) AS c FROM leistungsverzeichnisse WHERE standort = ?', name).c
            + get('SELECT COUNT(*) AS c FROM reinigungsaufgaben WHERE standort = ?', name).c
            + get('SELECT COUNT(*) AS c FROM protokolle WHERE standort = ?', name).c;
  if (used > 0) return res.status(400).json({ error: `Standort wird noch in ${used} Eintr\u00E4gen verwendet` });
  run('DELETE FROM standorte WHERE name = ?', name);
  audit('STANDORT_DEL', '', userName(req), `Standort gelöscht: ${name}`);
  save();
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════════
//  DIENSTLEISTER
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/dienstleister', requirePerm('dienstleister','lesen'), (req, res) => {
  const { q = '', aktiv = '' } = req.query;
  const where = ['1=1']; const params = [];
  if (q) { where.push('(name LIKE ? OR ansprechpartner LIKE ? OR email LIKE ?)'); const l=`%${q}%`; params.push(l,l,l); }
  if (aktiv !== '') { where.push('aktiv = ?'); params.push(parseInt(aktiv)); }
  res.json(all(`SELECT * FROM dienstleister WHERE ${where.join(' AND ')} ORDER BY name`, ...params));
});
app.post('/api/dienstleister', requirePerm('dienstleister','schreiben'), (req, res) => {
  const { name, ansprechpartner='', telefon='', email='', adresse='', vertrag_von='', vertrag_bis='', bemerkung='', aktiv=1 } = req.body;
  if (!name) return res.status(400).json({ error: 'Name fehlt' });
  run('INSERT INTO dienstleister (name,ansprechpartner,telefon,email,adresse,vertrag_von,vertrag_bis,bemerkung,aktiv,erstellt,geaendert_am,geaendert_von) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
      name, ansprechpartner, telefon, email, adresse, vertrag_von, vertrag_bis, bemerkung, aktiv ? 1 : 0, nowISO(), nowISO(), userName(req));
  audit('DIENSTLEISTER_NEU', '', userName(req), `Dienstleister angelegt: ${name}`);
  save();
  res.json({ success: true });
});
app.put('/api/dienstleister/:id', requirePerm('dienstleister','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!get('SELECT id FROM dienstleister WHERE id = ?', id)) return res.status(404).json({ error: 'Nicht gefunden' });
  const { name, ansprechpartner='', telefon='', email='', adresse='', vertrag_von='', vertrag_bis='', bemerkung='', aktiv=1 } = req.body;
  if (!name) return res.status(400).json({ error: 'Name fehlt' });
  run('UPDATE dienstleister SET name=?,ansprechpartner=?,telefon=?,email=?,adresse=?,vertrag_von=?,vertrag_bis=?,bemerkung=?,aktiv=?,geaendert_am=?,geaendert_von=? WHERE id=?',
      name, ansprechpartner, telefon, email, adresse, vertrag_von, vertrag_bis, bemerkung, aktiv ? 1 : 0, nowISO(), userName(req), id);
  audit('DIENSTLEISTER_EDIT', String(id), userName(req), `Dienstleister bearbeitet: ${name}`);
  save();
  res.json({ success: true });
});
app.delete('/api/dienstleister/:id', requirePerm('dienstleister','loeschen'), (req, res) => {
  const id = parseInt(req.params.id);
  const dl = get('SELECT name FROM dienstleister WHERE id = ?', id);
  if (!dl) return res.status(404).json({ error: 'Nicht gefunden' });
  const used = get('SELECT COUNT(*) AS c FROM reinigungsaufgaben WHERE dienstleister_id = ?', id).c
             + get('SELECT COUNT(*) AS c FROM leistungsverzeichnisse WHERE dienstleister_id = ?', id).c;
  if (used > 0) return res.status(400).json({ error: `Dienstleister wird noch in ${used} Eintr\u00E4gen verwendet` });
  run('DELETE FROM dienstleister WHERE id = ?', id);
  run('DELETE FROM kontakte WHERE dienstleister_id = ?', id);
  audit('DIENSTLEISTER_DEL', String(id), userName(req), `Dienstleister gelöscht: ${dl.name}`);
  save();
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════════
//  KONTAKTE
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/kontakte', requirePerm('kontakte','lesen'), (req, res) => {
  const { q = '', dienstleister_id = '' } = req.query;
  const where = ['1=1']; const params = [];
  if (dienstleister_id) { where.push('dienstleister_id = ?'); params.push(parseInt(dienstleister_id)); }
  if (q) { where.push('(name LIKE ? OR rolle LIKE ? OR email LIKE ? OR telefon LIKE ?)'); const l=`%${q}%`; params.push(l,l,l,l); }
  const rows = all(`SELECT k.*, d.name AS dienstleister_name FROM kontakte k LEFT JOIN dienstleister d ON d.id = k.dienstleister_id WHERE ${where.join(' AND ')} ORDER BY k.name`, ...params);
  res.json(rows);
});
app.post('/api/kontakte', requirePerm('kontakte','schreiben'), (req, res) => {
  const { dienstleister_id=null, name, rolle='', telefon='', mobil='', email='', bemerkung='' } = req.body;
  if (!name) return res.status(400).json({ error: 'Name fehlt' });
  run('INSERT INTO kontakte (dienstleister_id,name,rolle,telefon,mobil,email,bemerkung,erstellt) VALUES (?,?,?,?,?,?,?,?)',
      dienstleister_id || null, name, rolle, telefon, mobil, email, bemerkung, nowISO());
  audit('KONTAKT_NEU', '', userName(req), `Kontakt angelegt: ${name}`);
  save();
  res.json({ success: true });
});
app.put('/api/kontakte/:id', requirePerm('kontakte','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!get('SELECT id FROM kontakte WHERE id = ?', id)) return res.status(404).json({ error: 'Nicht gefunden' });
  const { dienstleister_id=null, name, rolle='', telefon='', mobil='', email='', bemerkung='' } = req.body;
  if (!name) return res.status(400).json({ error: 'Name fehlt' });
  run('UPDATE kontakte SET dienstleister_id=?,name=?,rolle=?,telefon=?,mobil=?,email=?,bemerkung=? WHERE id=?',
      dienstleister_id || null, name, rolle, telefon, mobil, email, bemerkung, id);
  audit('KONTAKT_EDIT', String(id), userName(req), `Kontakt bearbeitet: ${name}`);
  save();
  res.json({ success: true });
});
app.delete('/api/kontakte/:id', requirePerm('kontakte','loeschen'), (req, res) => {
  const id = parseInt(req.params.id);
  const k = get('SELECT name FROM kontakte WHERE id = ?', id);
  if (!k) return res.status(404).json({ error: 'Nicht gefunden' });
  run('DELETE FROM kontakte WHERE id = ?', id);
  audit('KONTAKT_DEL', String(id), userName(req), `Kontakt gelöscht: ${k.name}`);
  save();
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════════
//  LEISTUNGSVERZEICHNISSE (Upload + Parse)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/leistungsverzeichnisse', requirePerm('leistungsverzeichnisse','lesen'), (req, res) => {
  const { q='', standort='', dienstleister_id='', typ='' } = req.query;
  const where = ['1=1']; const params = [];
  const uSt = userStandort(req);
  if (uSt && uSt !== 'Alle') { where.push('lv.standort = ?'); params.push(uSt); }
  if (standort) { where.push('lv.standort = ?'); params.push(standort); }
  if (dienstleister_id) { where.push('lv.dienstleister_id = ?'); params.push(parseInt(dienstleister_id)); }
  if (typ) { where.push('lv.typ = ?'); params.push(typ); }
  if (q) { where.push('(lv.titel LIKE ? OR lv.dateiname LIKE ? OR lv.bemerkung LIKE ?)'); const l=`%${q}%`; params.push(l,l,l); }
  const rows = all(`SELECT lv.*, d.name AS dienstleister_name FROM leistungsverzeichnisse lv LEFT JOIN dienstleister d ON d.id = lv.dienstleister_id WHERE ${where.join(' AND ')} ORDER BY lv.hochgeladen_am DESC`, ...params);
  res.json(rows);
});

app.post('/api/leistungsverzeichnisse/upload', requirePerm('leistungsverzeichnisse','schreiben'), upload.single('datei'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Keine Datei' });
  const { standort='', dienstleister_id='', titel='', gueltig_von='', gueltig_bis='', bemerkung='' } = req.body;
  if (!standort) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'Standort fehlt' }); }

  const ext = path.extname(req.file.originalname).toLowerCase();
  let typ = 'sonstige';
  let extractedText = '';
  let parsedRows = null;

  try {
    if (ext === '.pdf') {
      typ = 'pdf';
      const buf = fs.readFileSync(req.file.path);
      try {
        const result = await pdfParse(buf);
        extractedText = (result.text || '').trim();
      } catch (e) {
        console.error('PDF-Parse-Fehler:', e.message);
      }
    } else if (ext === '.xlsx' || ext === '.xls' || ext === '.xlsm') {
      typ = 'excel';
      const wb = xlsx.readFile(req.file.path);
      const sheetName = wb.SheetNames[0];
      const ws = wb.Sheets[sheetName];
      parsedRows = xlsx.utils.sheet_to_json(ws, { defval: '', header: 1 }); // raw rows incl. headers
      // Auch als Text speichern
      extractedText = parsedRows.map(r => r.join(' | ')).join('\n');
    } else if (ext === '.csv') {
      typ = 'csv';
      const txt = fs.readFileSync(req.file.path, 'utf8');
      extractedText = txt;
      parsedRows = txt.split(/\r?\n/).map(line => line.split(/[;,\t]/));
    } else {
      typ = 'sonstige';
    }
  } catch (e) {
    console.error('Parse-Fehler:', e.message);
  }

  run(`INSERT INTO leistungsverzeichnisse (standort,dienstleister_id,titel,typ,dateiname,datei_pfad,gueltig_von,gueltig_bis,bemerkung,extrahierter_text,hochgeladen_am,hochgeladen_von)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      standort, dienstleister_id ? parseInt(dienstleister_id) : null, titel || req.file.originalname, typ,
      req.file.originalname, path.basename(req.file.path), gueltig_von, gueltig_bis, bemerkung, extractedText, nowISO(), userName(req));
  const lvId = get('SELECT last_insert_rowid() AS id').id;
  audit('LV_UPLOAD', String(lvId), userName(req), `Leistungsverzeichnis hochgeladen: ${req.file.originalname} (${typ})`);
  save();

  res.json({ success: true, id: lvId, typ, parsedRows: parsedRows ? parsedRows.slice(0, 200) : null, textPreview: extractedText.slice(0, 5000) });
});

app.get('/api/leistungsverzeichnisse/:id', requirePerm('leistungsverzeichnisse','lesen'), (req, res) => {
  const id = parseInt(req.params.id);
  const lv = get('SELECT lv.*, d.name AS dienstleister_name FROM leistungsverzeichnisse lv LEFT JOIN dienstleister d ON d.id = lv.dienstleister_id WHERE lv.id = ?', id);
  if (!lv) return res.status(404).json({ error: 'Nicht gefunden' });
  res.json(lv);
});

app.put('/api/leistungsverzeichnisse/:id', requirePerm('leistungsverzeichnisse','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!get('SELECT id FROM leistungsverzeichnisse WHERE id = ?', id)) return res.status(404).json({ error: 'Nicht gefunden' });
  const { titel='', standort='', dienstleister_id=null, gueltig_von='', gueltig_bis='', bemerkung='' } = req.body;
  run('UPDATE leistungsverzeichnisse SET titel=?,standort=?,dienstleister_id=?,gueltig_von=?,gueltig_bis=?,bemerkung=? WHERE id=?',
      titel, standort, dienstleister_id ? parseInt(dienstleister_id) : null, gueltig_von, gueltig_bis, bemerkung, id);
  audit('LV_EDIT', String(id), userName(req), `LV bearbeitet`);
  save();
  res.json({ success: true });
});

app.delete('/api/leistungsverzeichnisse/:id', requirePerm('leistungsverzeichnisse','loeschen'), (req, res) => {
  const id = parseInt(req.params.id);
  const lv = get('SELECT * FROM leistungsverzeichnisse WHERE id = ?', id);
  if (!lv) return res.status(404).json({ error: 'Nicht gefunden' });
  // Datei löschen
  try { fs.unlinkSync(path.join(UPLOADS_DIR, lv.datei_pfad)); } catch(_) {}
  run('DELETE FROM leistungsverzeichnisse WHERE id = ?', id);
  audit('LV_DEL', String(id), userName(req), `LV gelöscht: ${lv.dateiname}`);
  save();
  res.json({ success: true });
});

// ── LV-Datei downloaden ─────────────────────────────────────────────────────
app.get('/api/leistungsverzeichnisse/:id/download', requirePerm('leistungsverzeichnisse','lesen'), (req, res) => {
  const id = parseInt(req.params.id);
  const lv = get('SELECT * FROM leistungsverzeichnisse WHERE id = ?', id);
  if (!lv) return res.status(404).send('Nicht gefunden');
  const file = path.join(UPLOADS_DIR, lv.datei_pfad);
  if (!fs.existsSync(file)) return res.status(404).send('Datei nicht vorhanden');
  res.download(file, lv.dateiname);
});

// ── Excel-Daten erneut parsen (für nachträgliche Vorschau) ─────────────────
app.get('/api/leistungsverzeichnisse/:id/parse', requirePerm('leistungsverzeichnisse','lesen'), (req, res) => {
  const id = parseInt(req.params.id);
  const lv = get('SELECT * FROM leistungsverzeichnisse WHERE id = ?', id);
  if (!lv) return res.status(404).json({ error: 'Nicht gefunden' });
  const file = path.join(UPLOADS_DIR, lv.datei_pfad);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Datei nicht vorhanden' });

  if (lv.typ === 'excel') {
    const wb = xlsx.readFile(file);
    const sheetName = wb.SheetNames[0];
    const ws = wb.Sheets[sheetName];
    const rows = xlsx.utils.sheet_to_json(ws, { defval: '', header: 1 });
    return res.json({ typ: 'excel', rows: rows.slice(0, 500), sheetNames: wb.SheetNames });
  }
  if (lv.typ === 'pdf') {
    return res.json({ typ: 'pdf', text: lv.extrahierter_text || '' });
  }
  res.json({ typ: lv.typ, text: lv.extrahierter_text || '' });
});

// ── Aufgaben aus Excel-Zeilen importieren ───────────────────────────────────
app.post('/api/leistungsverzeichnisse/:id/import-aufgaben', requirePerm('aufgaben','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  const lv = get('SELECT * FROM leistungsverzeichnisse WHERE id = ?', id);
  if (!lv) return res.status(404).json({ error: 'LV nicht gefunden' });
  const { aufgaben } = req.body;
  if (!Array.isArray(aufgaben) || aufgaben.length === 0) return res.status(400).json({ error: 'Keine Aufgaben übergeben' });

  let imported = 0;
  for (const a of aufgaben) {
    const taetigkeit = (a.taetigkeit || '').trim();
    if (!taetigkeit) continue;
    run(`INSERT INTO reinigungsaufgaben (leistungsverzeichnis_id,standort,dienstleister_id,bereich,raum,taetigkeit,frequenz,wochentag,uhrzeit,ausfuehrender,bemerkung,aktiv,erstellt,geaendert_am,geaendert_von)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)`,
        id, a.standort || lv.standort, lv.dienstleister_id || null,
        a.bereich || '', a.raum || '', taetigkeit,
        a.frequenz || '', a.wochentag || '', a.uhrzeit || '',
        a.ausfuehrender || '', a.bemerkung || '',
        nowISO(), nowISO(), userName(req));
    imported++;
  }
  audit('AUFGABEN_IMPORT', String(id), userName(req), `${imported} Aufgaben importiert aus LV ${lv.dateiname}`);
  save();
  res.json({ success: true, imported });
});

// ── Aufgaben aus PDF-Text extrahieren ───────────────────────────────────────
app.post('/api/leistungsverzeichnisse/:id/extract-aufgaben', requirePerm('aufgaben','schreiben'), async (req, res) => {
  const id = parseInt(req.params.id);
  const lv = get('SELECT * FROM leistungsverzeichnisse WHERE id = ?', id);
  if (!lv) return res.status(404).json({ error: 'LV nicht gefunden' });

  let text = lv.extrahierter_text || '';
  // Falls kein Text gespeichert, erneut parsen
  if (!text && lv.typ === 'pdf') {
    const file = path.join(UPLOADS_DIR, lv.datei_pfad);
    if (fs.existsSync(file)) {
      try {
        const buf = fs.readFileSync(file);
        const result = await pdfParse(buf);
        text = (result.text || '').trim();
      } catch(e) { return res.status(500).json({ error: 'PDF konnte nicht gelesen werden' }); }
    }
  }
  if (!text) return res.json({ aufgaben: [], hinweis: 'Kein Text im Dokument gefunden' });

  // Intelligente Extraktion von Reinigungsaufgaben
  const aufgaben = extractTasksFromText(text, lv.standort);
  res.json({ aufgaben, standort: lv.standort, dienstleister_id: lv.dienstleister_id, quelldatei: lv.dateiname });
});

/**
 * Extrahiert Reinigungsaufgaben aus dem Text eines Leistungsverzeichnisses.
 * Erkennt Bereiche/Räume, Tätigkeiten und Frequenzen.
 */
function extractTasksFromText(text, standort) {
  const aufgaben = [];
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 2);

  // Frequenz-Patterns
  const freqPatterns = [
    { regex: /\b(t[äa]glich|jeden\s*tag|arbeitst[äa]glich|werkt[äa]glich)\b/i, freq: 'täglich' },
    { regex: /\b(\d+)\s*[x×]\s*(t[äa]glich|pro\s*tag|\/\s*tag)/i, freq: m => m[1]+'x täglich' },
    { regex: /\b(\d+)\s*[x×]\s*(w[öo]chentlich|pro\s*woche|\/\s*woche)/i, freq: m => m[1]+'x wöchentlich' },
    { regex: /\bw[öo]chentlich\b/i, freq: 'wöchentlich' },
    { regex: /\b(2|zwei)\s*[x×]?\s*(w[öo]chentlich|pro\s*woche)/i, freq: '2x wöchentlich' },
    { regex: /\b(3|drei)\s*[x×]?\s*(w[öo]chentlich|pro\s*woche)/i, freq: '3x wöchentlich' },
    { regex: /\bmonatlich\b/i, freq: 'monatlich' },
    { regex: /\b(\d+)\s*[x×]\s*(monatlich|pro\s*monat|\/\s*monat)/i, freq: m => m[1]+'x monatlich' },
    { regex: /\bquartal(sw[ei]se|sm[äa][ßs]ig)?\b/i, freq: 'quartalsweise' },
    { regex: /\bj[äa]hrlich\b/i, freq: 'jährlich' },
    { regex: /\bhalb\s*j[äa]hrlich\b/i, freq: 'halbjährlich' },
    { regex: /\bbei\s*bedarf\b/i, freq: 'bei Bedarf' },
    { regex: /\bnach\s*bedarf\b/i, freq: 'bei Bedarf' },
  ];

  // Bereich/Raum-Keywords
  const bereichKeywords = [
    'flur', 'treppenhaus', 'eingang', 'foyer', 'empfang', 'rezeption',
    'büro', 'buro', 'verwaltung', 'seminar', 'hörsaal', 'horsaal',
    'toilette', 'wc', 'sanitär', 'sanitar', 'dusche', 'bad',
    'küche', 'kuche', 'teeküche', 'teekuche', 'kantine', 'mensa',
    'keller', 'lager', 'archiv', 'technik', 'server',
    'aufzug', 'fahrstuhl', 'parkhaus', 'tiefgarage', 'garage',
    'konferenz', 'besprechung', 'meeting', 'schulung',
    'bibliothek', 'labor', 'werkstatt', 'umkleide', 'sport', 'aula',
  ];

  // Reinigungs-Tätigkeits-Keywords (Zeilen die diese enthalten, sind wahrscheinlich Aufgaben)
  const taskKeywords = [
    'reinig', 'wisch', 'saug', 'feg', 'kehr', 'putz',
    'desinf', 'entleer', 'leeren', 'entsorgen', 'müll', 'abfall',
    'polier', 'pflege', 'trockn', 'nass', 'feucht',
    'glas', 'fenster', 'spiegel',
    'staub', 'abstauben', 'wischen',
    'boden', 'belag', 'teppich', 'parkett', 'fliese',
    'möbel', 'tisch', 'stuhl', 'schreibtisch', 'regal',
    'papierkorb', 'mülleimer', 'abfalleimer',
    'seife', 'handtuch', 'spender', 'nachfüll', 'auffüll',
    'hygiene', 'sanitär',
  ];

  let currentBereich = '';
  let currentRaum = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineLower = line.toLowerCase();

    // Erkenne Bereich/Raum-Überschriften (kurze Zeilen, oft gefolgt von Aufgaben)
    const isShortHeader = line.length < 60 && !line.endsWith('.') && !line.endsWith(',');
    const matchesBereich = bereichKeywords.some(k => lineLower.includes(k));
    if (isShortHeader && matchesBereich && !taskKeywords.some(k => lineLower.includes(k))) {
      // Prüfe ob es eher ein Bereich oder Raum ist
      if (/\d/.test(line) || /raum|zimmer|nr/i.test(line)) {
        currentRaum = line.replace(/^[\d\.\-\s:]+/, '').trim();
      } else {
        currentBereich = line.replace(/^[\d\.\-\s:]+/, '').trim();
        currentRaum = '';
      }
      continue;
    }

    // Prüfe ob Zeile eine Aufgabe ist
    const isTask = taskKeywords.some(k => lineLower.includes(k));
    if (!isTask) continue;

    // Zu kurz oder offensichtlich nur ein Header
    if (line.length < 8) continue;

    // Frequenz erkennen
    let frequenz = '';
    for (const fp of freqPatterns) {
      const match = line.match(fp.regex);
      if (match) {
        frequenz = typeof fp.freq === 'function' ? fp.freq(match) : fp.freq;
        break;
      }
    }

    // Tätigkeit bereinigen (Frequenz-Teile ggf. belassen, da informativ)
    let taetigkeit = line
      .replace(/^[\d\.\-\)\]\s:]+/, '')  // führende Nummern entfernen
      .replace(/^\s*[-–•]\s*/, '')        // Aufzählungszeichen
      .trim();

    if (taetigkeit.length < 5) continue;

    aufgaben.push({
      taetigkeit,
      bereich: currentBereich,
      raum: currentRaum,
      frequenz,
      standort: standort || '',
      wochentag: '',
      uhrzeit: '',
      ausfuehrender: '',
      bemerkung: '',
    });
  }

  return aufgaben;
}

// ════════════════════════════════════════════════════════════════════════════
//  REINIGUNGSAUFGABEN
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/aufgaben', requirePerm('aufgaben','lesen'), (req, res) => {
  const { q='', standort='', dienstleister_id='', frequenz='', wochentag='', aktiv='' } = req.query;
  const where = ['1=1']; const params = [];
  const uSt = userStandort(req);
  if (uSt && uSt !== 'Alle') { where.push('a.standort = ?'); params.push(uSt); }
  if (standort) { where.push('a.standort = ?'); params.push(standort); }
  if (dienstleister_id) { where.push('a.dienstleister_id = ?'); params.push(parseInt(dienstleister_id)); }
  if (frequenz) { where.push('a.frequenz = ?'); params.push(frequenz); }
  if (wochentag) { where.push('a.wochentag = ?'); params.push(wochentag); }
  if (aktiv !== '') { where.push('a.aktiv = ?'); params.push(parseInt(aktiv)); }
  if (q) { where.push('(a.taetigkeit LIKE ? OR a.bereich LIKE ? OR a.raum LIKE ? OR a.ausfuehrender LIKE ? OR a.bemerkung LIKE ?)'); const l=`%${q}%`; params.push(l,l,l,l,l); }
  const rows = all(`SELECT a.*, d.name AS dienstleister_name FROM reinigungsaufgaben a LEFT JOIN dienstleister d ON d.id = a.dienstleister_id WHERE ${where.join(' AND ')} ORDER BY a.standort, a.bereich, a.taetigkeit`, ...params);
  res.json(rows);
});

app.post('/api/aufgaben', requirePerm('aufgaben','schreiben'), (req, res) => {
  const { standort, dienstleister_id=null, leistungsverzeichnis_id=null, bereich='', raum='', taetigkeit, frequenz='', wochentag='', uhrzeit='', ausfuehrender='', bemerkung='', aktiv=1 } = req.body;
  if (!standort) return res.status(400).json({ error: 'Standort fehlt' });
  if (!taetigkeit) return res.status(400).json({ error: 'Tätigkeit fehlt' });
  run(`INSERT INTO reinigungsaufgaben (leistungsverzeichnis_id,standort,dienstleister_id,bereich,raum,taetigkeit,frequenz,wochentag,uhrzeit,ausfuehrender,bemerkung,aktiv,erstellt,geaendert_am,geaendert_von)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      leistungsverzeichnis_id ? parseInt(leistungsverzeichnis_id) : null,
      standort, dienstleister_id ? parseInt(dienstleister_id) : null,
      bereich, raum, taetigkeit, frequenz, wochentag, uhrzeit, ausfuehrender, bemerkung,
      aktiv ? 1 : 0, nowISO(), nowISO(), userName(req));
  audit('AUFGABE_NEU', '', userName(req), `Aufgabe angelegt: ${taetigkeit} (${standort})`);
  save();
  res.json({ success: true });
});

app.put('/api/aufgaben/:id', requirePerm('aufgaben','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!get('SELECT id FROM reinigungsaufgaben WHERE id = ?', id)) return res.status(404).json({ error: 'Nicht gefunden' });
  const { standort, dienstleister_id=null, leistungsverzeichnis_id=null, bereich='', raum='', taetigkeit, frequenz='', wochentag='', uhrzeit='', ausfuehrender='', bemerkung='', aktiv=1 } = req.body;
  if (!standort || !taetigkeit) return res.status(400).json({ error: 'Pflichtfelder fehlen' });
  run(`UPDATE reinigungsaufgaben SET leistungsverzeichnis_id=?,standort=?,dienstleister_id=?,bereich=?,raum=?,taetigkeit=?,frequenz=?,wochentag=?,uhrzeit=?,ausfuehrender=?,bemerkung=?,aktiv=?,geaendert_am=?,geaendert_von=? WHERE id=?`,
      leistungsverzeichnis_id ? parseInt(leistungsverzeichnis_id) : null,
      standort, dienstleister_id ? parseInt(dienstleister_id) : null,
      bereich, raum, taetigkeit, frequenz, wochentag, uhrzeit, ausfuehrender, bemerkung,
      aktiv ? 1 : 0, nowISO(), userName(req), id);
  audit('AUFGABE_EDIT', String(id), userName(req), `Aufgabe bearbeitet: ${taetigkeit}`);
  save();
  res.json({ success: true });
});

app.delete('/api/aufgaben/:id', requirePerm('aufgaben','loeschen'), (req, res) => {
  const id = parseInt(req.params.id);
  const a = get('SELECT taetigkeit FROM reinigungsaufgaben WHERE id = ?', id);
  if (!a) return res.status(404).json({ error: 'Nicht gefunden' });
  run('DELETE FROM reinigungsaufgaben WHERE id = ?', id);
  audit('AUFGABE_DEL', String(id), userName(req), `Aufgabe gelöscht: ${a.taetigkeit}`);
  save();
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════════
//  PROTOKOLLE
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/protokolle', requirePerm('protokolle','lesen'), (req, res) => {
  const { q='', standort='', dienstleister_id='', von='', bis='' } = req.query;
  const where = ['1=1']; const params = [];
  const uSt = userStandort(req);
  if (uSt && uSt !== 'Alle') { where.push('p.standort = ?'); params.push(uSt); }
  if (standort) { where.push('p.standort = ?'); params.push(standort); }
  if (dienstleister_id) { where.push('p.dienstleister_id = ?'); params.push(parseInt(dienstleister_id)); }
  if (von) { where.push('p.datum >= ?'); params.push(von); }
  if (bis) { where.push('p.datum <= ?'); params.push(bis); }
  if (q) { where.push('(p.maengel LIKE ? OR p.bemerkung LIKE ? OR p.durchgefuehrt_von LIKE ?)'); const l=`%${q}%`; params.push(l,l,l); }
  const rows = all(`SELECT p.*, d.name AS dienstleister_name FROM protokolle p LEFT JOIN dienstleister d ON d.id = p.dienstleister_id WHERE ${where.join(' AND ')} ORDER BY p.datum DESC, p.id DESC`, ...params);
  res.json(rows);
});

app.post('/api/protokolle', requirePerm('protokolle','schreiben'), (req, res) => {
  const { datum, standort, dienstleister_id=null, durchgefuehrt_von='', qualitaet=0, maengel='', bemerkung='', kontrolliert_von='' } = req.body;
  if (!datum || !standort) return res.status(400).json({ error: 'Datum und Standort sind Pflicht' });
  run(`INSERT INTO protokolle (datum,standort,dienstleister_id,durchgefuehrt_von,qualitaet,maengel,bemerkung,kontrolliert_von,erstellt,erstellt_von)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      datum, standort, dienstleister_id ? parseInt(dienstleister_id) : null,
      durchgefuehrt_von, parseInt(qualitaet) || 0, maengel, bemerkung, kontrolliert_von || userName(req),
      nowISO(), userName(req));
  audit('PROTOKOLL_NEU', '', userName(req), `Protokoll erstellt: ${standort} (${datum})`);
  save();
  res.json({ success: true });
});

app.put('/api/protokolle/:id', requirePerm('protokolle','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!get('SELECT id FROM protokolle WHERE id = ?', id)) return res.status(404).json({ error: 'Nicht gefunden' });
  const { datum, standort, dienstleister_id=null, durchgefuehrt_von='', qualitaet=0, maengel='', bemerkung='', kontrolliert_von='' } = req.body;
  if (!datum || !standort) return res.status(400).json({ error: 'Datum und Standort sind Pflicht' });
  run(`UPDATE protokolle SET datum=?,standort=?,dienstleister_id=?,durchgefuehrt_von=?,qualitaet=?,maengel=?,bemerkung=?,kontrolliert_von=? WHERE id=?`,
      datum, standort, dienstleister_id ? parseInt(dienstleister_id) : null,
      durchgefuehrt_von, parseInt(qualitaet) || 0, maengel, bemerkung, kontrolliert_von,
      id);
  audit('PROTOKOLL_EDIT', String(id), userName(req), `Protokoll bearbeitet`);
  save();
  res.json({ success: true });
});

app.delete('/api/protokolle/:id', requirePerm('protokolle','loeschen'), (req, res) => {
  const id = parseInt(req.params.id);
  const p = get('SELECT * FROM protokolle WHERE id = ?', id);
  if (!p) return res.status(404).json({ error: 'Nicht gefunden' });
  // Dokumente löschen
  const docs = all('SELECT * FROM protokoll_dokumente WHERE protokoll_id = ?', id);
  for (const d of docs) {
    try { fs.unlinkSync(path.join(UPLOADS_DIR, d.datei_pfad)); } catch(_) {}
  }
  run('DELETE FROM protokoll_dokumente WHERE protokoll_id = ?', id);
  run('DELETE FROM protokolle WHERE id = ?', id);
  audit('PROTOKOLL_DEL', String(id), userName(req), `Protokoll gelöscht (${p.standort}, ${p.datum})`);
  save();
  res.json({ success: true });
});

app.post('/api/protokolle/:id/upload', requirePerm('protokolle','schreiben'), upload.single('datei'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!req.file) return res.status(400).json({ error: 'Keine Datei' });
  if (!get('SELECT id FROM protokolle WHERE id = ?', id)) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Protokoll nicht gefunden' });
  }
  run('INSERT INTO protokoll_dokumente (protokoll_id, datei_pfad, dateiname, hochgeladen_am) VALUES (?,?,?,?)',
      id, path.basename(req.file.path), req.file.originalname, nowISO());
  audit('PROTOKOLL_DOK', String(id), userName(req), `Dokument hochgeladen: ${req.file.originalname}`);
  save();
  res.json({ success: true });
});

app.get('/api/protokolle/:id/dokumente', requirePerm('protokolle','lesen'), (req, res) => {
  const id = parseInt(req.params.id);
  res.json(all('SELECT * FROM protokoll_dokumente WHERE protokoll_id = ? ORDER BY hochgeladen_am', id));
});

// ════════════════════════════════════════════════════════════════════════════
//  BENUTZER
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/benutzer', requirePerm('benutzer','lesen'), (req, res) => {
  res.json(all('SELECT * FROM benutzer ORDER BY name'));
});
app.post('/api/benutzer', requirePerm('benutzer','schreiben'), (req, res) => {
  const { ad_user='', name, email='', rolle='Lesezugriff', standort='Alle', aktiv=1 } = req.body;
  if (!name) return res.status(400).json({ error: 'Name fehlt' });
  if (ad_user && get('SELECT id FROM benutzer WHERE LOWER(ad_user) = LOWER(?)', ad_user)) return res.status(400).json({ error: 'AD-User existiert bereits' });
  run('INSERT INTO benutzer (ad_user,name,email,rolle,standort,aktiv) VALUES (?,?,?,?,?,?)',
      ad_user, name, email, rolle, standort || 'Alle', aktiv ? 1 : 0);
  audit('BENUTZER_NEU', '', userName(req), `Benutzer angelegt: ${name} (${rolle})`);
  save();
  res.json({ success: true });
});
app.put('/api/benutzer/:id', requirePerm('benutzer','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  if (!get('SELECT id FROM benutzer WHERE id = ?', id)) return res.status(404).json({ error: 'Nicht gefunden' });
  const { rolle, standort='Alle', aktiv=1 } = req.body;
  run('UPDATE benutzer SET rolle=?,standort=?,aktiv=? WHERE id=?', rolle, standort || 'Alle', aktiv ? 1 : 0, id);
  audit('BENUTZER_EDIT', String(id), userName(req), `Benutzer bearbeitet (Rolle: ${rolle})`);
  save();
  res.json({ success: true });
});
app.delete('/api/benutzer/:id', requirePerm('benutzer','loeschen'), (req, res) => {
  const id = parseInt(req.params.id);
  const u = get('SELECT name FROM benutzer WHERE id = ?', id);
  if (!u) return res.status(404).json({ error: 'Nicht gefunden' });
  run('DELETE FROM benutzer WHERE id = ?', id);
  audit('BENUTZER_DEL', String(id), userName(req), `Benutzer gelöscht: ${u.name}`);
  save();
  res.json({ success: true });
});

// ── AD Search ───────────────────────────────────────────────────────────────
app.post('/api/ad-search', requirePerm('benutzer','schreiben'), async (req, res) => {
  const { query } = req.body;
  if (!query || query.length < 2) return res.status(400).json({ error: 'Mindestens 2 Zeichen' });
  if (!req.session.adCreds) return res.status(401).json({ error: 'AD-Sitzung abgelaufen, bitte neu anmelden' });
  try {
    const users = await ldapSearch(query, req.session.adCreds);
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: 'AD-Suche fehlgeschlagen: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  BERECHTIGUNGEN
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/berechtigungen', requirePerm('berechtigungen','lesen'), (req, res) => {
  res.json(all('SELECT * FROM berechtigungen ORDER BY rolle, bereich'));
});
app.put('/api/berechtigungen/:id', requirePerm('berechtigungen','schreiben'), (req, res) => {
  const id = parseInt(req.params.id);
  const { lesen=0, schreiben=0, loeschen=0 } = req.body;
  run('UPDATE berechtigungen SET lesen=?,schreiben=?,loeschen=? WHERE id=?',
      lesen ? 1 : 0, schreiben ? 1 : 0, loeschen ? 1 : 0, id);
  audit('BERECHTIGUNG_EDIT', String(id), userName(req), `Berechtigung geändert`);
  save();
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════════
//  AUDIT-LOG
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/auditlog', requirePerm('auditlog','lesen'), (req, res) => {
  const { q='', aktion='', von='', bis='', page='1', limit='50' } = req.query;
  const where = ['1=1']; const params = [];
  if (aktion) { where.push('aktion = ?'); params.push(aktion); }
  if (von) { where.push('zeitstempel >= ?'); params.push(von); }
  if (bis) { where.push('zeitstempel <= ?'); params.push(bis + 'T23:59:59'); }
  if (q) { where.push('(objekt_id LIKE ? OR benutzer LIKE ? OR details LIKE ?)'); const l=`%${q}%`; params.push(l,l,l); }
  const p = Math.max(1, parseInt(page) || 1);
  const l = Math.max(1, Math.min(500, parseInt(limit) || 50));
  const total = get(`SELECT COUNT(*) AS c FROM audit_log WHERE ${where.join(' AND ')}`, ...params).c;
  const rows = all(`SELECT * FROM audit_log WHERE ${where.join(' AND ')} ORDER BY zeitstempel DESC LIMIT ? OFFSET ?`, ...params, l, (p-1)*l);
  res.json({ rows, total, page: p, limit: l });
});

// ════════════════════════════════════════════════════════════════════════════
//  DASHBOARD-STATS
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/stats', (req, res) => {
  const uSt = userStandort(req);
  const stFilter = uSt && uSt !== 'Alle' ? ` WHERE standort = '${uSt.replace(/'/g, "''")}'` : '';
  const counts = {
    standorte:        get('SELECT COUNT(*) AS c FROM standorte').c,
    dienstleister:    get('SELECT COUNT(*) AS c FROM dienstleister WHERE aktiv = 1').c,
    leistungsverzeichnisse: get(`SELECT COUNT(*) AS c FROM leistungsverzeichnisse${stFilter}`).c,
    aufgaben:         get(`SELECT COUNT(*) AS c FROM reinigungsaufgaben${stFilter}${stFilter ? ' AND' : ' WHERE'} aktiv = 1`).c,
    protokolle_30tg:  get(`SELECT COUNT(*) AS c FROM protokolle WHERE datum >= date('now','-30 days')${stFilter ? ' AND standort = ?' : ''}`, ...(stFilter ? [uSt] : [])).c,
    maengel_offen:    get(`SELECT COUNT(*) AS c FROM protokolle WHERE maengel != ''${stFilter ? ' AND standort = ?' : ''}`, ...(stFilter ? [uSt] : [])).c
  };
  res.json(counts);
});

// ── Fallback / SPA ─────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ───────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`Reinigungsmanagement läuft auf Port ${PORT}`));
}).catch(err => {
  console.error('DB-Init fehlgeschlagen:', err);
  process.exit(1);
});
