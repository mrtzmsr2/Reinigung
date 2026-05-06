const initSqlJs = require('sql.js');
const fs   = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'reinigung.db');
let _db;

// ── Public Helpers ──────────────────────────────────────────────────────────
function all(sql, ...params) {
  const stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function get(sql, ...params) {
  const rows = all(sql, ...params);
  return rows[0] || null;
}
function run(sql, ...params) {
  if (params.length) _db.run(sql, params);
  else _db.run(sql);
}
function exec(sql) { _db.exec(sql); }
function save() { fs.writeFileSync(DB_PATH, Buffer.from(_db.export())); }

// ── Schema ──────────────────────────────────────────────────────────────────
function createSchema() {
  exec(`
    CREATE TABLE IF NOT EXISTS standorte (
      id   INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS benutzer (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      ad_user        TEXT DEFAULT '',
      name           TEXT NOT NULL,
      email          TEXT NOT NULL,
      rolle          TEXT NOT NULL,
      standort       TEXT DEFAULT 'Alle',
      aktiv          INTEGER DEFAULT 1,
      letzter_login  TEXT
    );

    CREATE TABLE IF NOT EXISTS berechtigungen (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      rolle      TEXT NOT NULL,
      bereich    TEXT NOT NULL,
      lesen      INTEGER DEFAULT 1,
      schreiben  INTEGER DEFAULT 0,
      loeschen   INTEGER DEFAULT 0,
      UNIQUE(rolle, bereich)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      zeitstempel    TEXT NOT NULL,
      aktion         TEXT NOT NULL,
      objekt_id      TEXT,
      benutzer       TEXT,
      details        TEXT
    );

    CREATE TABLE IF NOT EXISTS dienstleister (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT NOT NULL,
      ansprechpartner TEXT DEFAULT '',
      telefon       TEXT DEFAULT '',
      email         TEXT DEFAULT '',
      adresse       TEXT DEFAULT '',
      vertrag_von   TEXT DEFAULT '',
      vertrag_bis   TEXT DEFAULT '',
      bemerkung     TEXT DEFAULT '',
      aktiv         INTEGER DEFAULT 1,
      erstellt      TEXT NOT NULL,
      geaendert_am  TEXT DEFAULT '',
      geaendert_von TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS kontakte (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      dienstleister_id INTEGER,
      name            TEXT NOT NULL,
      rolle           TEXT DEFAULT '',
      telefon         TEXT DEFAULT '',
      mobil           TEXT DEFAULT '',
      email           TEXT DEFAULT '',
      bemerkung       TEXT DEFAULT '',
      erstellt        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS leistungsverzeichnisse (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      standort        TEXT NOT NULL,
      dienstleister_id INTEGER,
      titel           TEXT DEFAULT '',
      typ             TEXT NOT NULL,
      dateiname       TEXT NOT NULL,
      datei_pfad      TEXT NOT NULL,
      gueltig_von     TEXT DEFAULT '',
      gueltig_bis     TEXT DEFAULT '',
      bemerkung       TEXT DEFAULT '',
      extrahierter_text TEXT DEFAULT '',
      hochgeladen_am  TEXT NOT NULL,
      hochgeladen_von TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS reinigungsaufgaben (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      leistungsverzeichnis_id INTEGER,
      standort          TEXT NOT NULL,
      dienstleister_id  INTEGER,
      bereich           TEXT DEFAULT '',
      raum              TEXT DEFAULT '',
      taetigkeit        TEXT NOT NULL,
      frequenz          TEXT DEFAULT '',
      wochentag         TEXT DEFAULT '',
      uhrzeit           TEXT DEFAULT '',
      ausfuehrender     TEXT DEFAULT '',
      bemerkung         TEXT DEFAULT '',
      aktiv             INTEGER DEFAULT 1,
      erstellt          TEXT NOT NULL,
      geaendert_am      TEXT DEFAULT '',
      geaendert_von     TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS protokolle (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      datum           TEXT NOT NULL,
      standort        TEXT NOT NULL,
      dienstleister_id INTEGER,
      durchgefuehrt_von TEXT DEFAULT '',
      qualitaet       INTEGER DEFAULT 0,
      maengel         TEXT DEFAULT '',
      bemerkung       TEXT DEFAULT '',
      kontrolliert_von TEXT DEFAULT '',
      erstellt        TEXT NOT NULL,
      erstellt_von    TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS protokoll_dokumente (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      protokoll_id    INTEGER NOT NULL,
      datei_pfad      TEXT NOT NULL,
      dateiname       TEXT DEFAULT '',
      hochgeladen_am  TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_lv_standort ON leistungsverzeichnisse(standort);
    CREATE INDEX IF NOT EXISTS idx_ra_standort ON reinigungsaufgaben(standort);
    CREATE INDEX IF NOT EXISTS idx_ra_freq    ON reinigungsaufgaben(frequenz);
    CREATE INDEX IF NOT EXISTS idx_ra_dl      ON reinigungsaufgaben(dienstleister_id);
    CREATE INDEX IF NOT EXISTS idx_pr_standort ON protokolle(standort);
    CREATE INDEX IF NOT EXISTS idx_pr_datum   ON protokolle(datum);
    CREATE INDEX IF NOT EXISTS idx_al_aktion  ON audit_log(aktion);
  `);
}

// ── Seed ────────────────────────────────────────────────────────────────────
function seed() {
  // Standorte
  if (get('SELECT COUNT(*) AS c FROM standorte').c === 0) {
    console.log('Seeding Standorte …');
    const STANDORTE = [
      'Aachen','Augsburg','Berlin','Bochum','Bonn','Bönen','Bremen',
      'Dortmund','Duisburg','Düsseldorf','Essen','Frankfurt am Main',
      'Gütersloh','Hagen','Hamburg','Hannover','Herne','Karlsruhe',
      'Kassel','Koblenz','Köln Ehrenfeld','Köln Agrippinawerft','Leipzig',
      'Magdeburg','Mainz','Mannheim','Marl','München','Münster','Neuss',
      'Nürnberg','Oberhausen','Offenbach','Saarbrücken','Siegen',
      'Stuttgart','Wesel','Wuppertal','Lippstadt','Arnsberg','Wien'
    ];
    const ins = _db.prepare('INSERT INTO standorte (name) VALUES (?)');
    for (const s of STANDORTE) ins.run([s]);
    ins.free();
    save();
    console.log(`Standorte geseedet: ${STANDORTE.length}`);
  }

  // Initial-Admin
  if (get('SELECT COUNT(*) AS c FROM benutzer').c === 0) {
    console.log('Seeding Initial-Admin …');
    run(`INSERT INTO benutzer (ad_user, name, email, rolle, standort, aktiv)
         VALUES ('benedikt.glingener', 'Benedikt Glingener', '', 'Super-Admin', 'Alle', 1)`);
    save();
  }

  // Berechtigungen
  if (get('SELECT COUNT(*) AS c FROM berechtigungen').c === 0) {
    console.log('Seeding Berechtigungen …');
    const BEREICHE = ['dashboard','standorte','dienstleister','kontakte','leistungsverzeichnisse','aufgaben','protokolle','benutzer','auditlog','berechtigungen'];
    const ROLLEN = {
      'Super-Admin'    : { lesen:1, schreiben:1, loeschen:1 },
      'Standortadmin'  : { lesen:1, schreiben:1, loeschen:0 },
      'Sachbearbeiter' : { lesen:1, schreiben:1, loeschen:0 },
      'Lesezugriff'    : { lesen:1, schreiben:0, loeschen:0 }
    };
    for (const rolle of Object.keys(ROLLEN)) {
      for (const bereich of BEREICHE) {
        const p = ROLLEN[rolle];
        // Berechtigungen-Bereich nur Super-Admin
        const eff = (bereich === 'berechtigungen' && rolle !== 'Super-Admin')
          ? { lesen:0, schreiben:0, loeschen:0 } : p;
        run('INSERT INTO berechtigungen (rolle,bereich,lesen,schreiben,loeschen) VALUES (?,?,?,?,?)',
            rolle, bereich, eff.lesen, eff.schreiben, eff.loeschen);
      }
    }
    save();
  }
}

// ── Init ────────────────────────────────────────────────────────────────────
async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    _db = new SQL.Database(buf);
    console.log(`DB geladen: ${DB_PATH}`);
  } else {
    _db = new SQL.Database();
    console.log('Neue DB initialisiert');
  }

  createSchema();
  save();
  seed();
  return _db;
}

module.exports = { initDB, all, get, run, exec, save };
