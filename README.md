# FOM Reinigungsmanagement

Web-Anwendung zur Verwaltung von Reinigungsdienstleistungen für die FOM-Standorte.

## Module

| Modul | Beschreibung |
|---|---|
| **Standorte** | Verwaltung der FOM-Studienzentren |
| **Dienstleister** | Reinigungsfirmen mit Vertragsdaten |
| **Kontakte** | Ansprechpartner pro Dienstleister |
| **Leistungsverzeichnisse** | PDF-/Excel-Upload, automatische Umwandlung von Excel in strukturierte Daten, Textextraktion aus PDFs |
| **Reinigungsaufgaben** | Wer reinigt wann was wo – filterbare Tabelle |
| **Protokolle** | Erledigt-Quittung, Mängelmeldungen, Fotos |
| **Benutzer & Berechtigungen** | LDAP-Anbindung, Rollensystem |
| **Audit-Log** | Alle Aktionen werden protokolliert |

## Tech-Stack

* Node.js + Express 4
* sql.js (SQLite, persistiert auf Disk)
* ldapjs (Authentifizierung gegen Active Directory)
* multer (Datei-Upload)
* xlsx (Excel-Parsing)
* pdf-parse (PDF-Textextraktion)
* Vanilla-JS-SPA (Single-File `public/index.html`)

## Installation

```bash
npm install
node server.js
```

App läuft standardmäßig auf Port `6122`.

## PM2 Deployment

```bash
pm2 start ecosystem.config.js
```

## Verzeichnisstruktur

```
Reinigung/
├── server.js              # Express-Server + REST-API
├── database.js            # sql.js Schema + Seed
├── package.json
├── ecosystem.config.js    # PM2-Konfiguration
├── public/
│   └── index.html         # SPA
└── uploads/               # Hochgeladene LV-Dateien (PDF/Excel)
```

## Standard-Login

Login per AD-Username (`vorname.nachname`) gegen `ldap://10.17.113.136`.
Initial-Admin: `benedikt.glingener` (Super-Admin).
