// Temp-mail self-hosted app with built-in SMTP receiver.
// - Run an SMTP server that accepts any recipient @mail.<yourdomain> and saves messages.
// - Inboxes can be created with passwords. To view messages, client must provide X-INBOX-PW header.
// - Messages older than 30 days are deleted automatically.
require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const multer = require('multer');
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const bodyParser = require('body-parser');

const PORT = process.env.PORT || 3000;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '2525', 10); // default 2525 for testing
const DB_FILE = process.env.DB_FILE || '/data/mail.db';
const ATTACH_DIR = path.join(__dirname, 'attachments');

if (!fs.existsSync(ATTACH_DIR)) fs.mkdirSync(ATTACH_DIR, { recursive: true });
const dataDir = path.dirname(DB_FILE);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS inboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    localpart TEXT UNIQUE,
    pw_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    localpart TEXT,
    sender TEXT,
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    headers TEXT,
    attachments TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

const app = express();
app.use(helmet());
app.use(bodyParser.json());
app.use('/', express.static(path.join(__dirname, 'public')));
app.use('/attachments', express.static(ATTACH_DIR, { dotfiles: 'deny', index: false }));

// helper: check inbox password
function verifyInboxPassword(localpart, password) {
  return new Promise((resolve, reject) => {
    db.get('SELECT pw_hash FROM inboxes WHERE localpart = ?', [localpart], (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve(false);
      bcrypt.compare(password, row.pw_hash, (e, res) => {
        if (e) return reject(e);
        resolve(res);
      });
    });
  });
}

// create inbox
app.post('/api/create', async (req, res) => {
  try {
    let { localpart, password } = req.body || {};
    if (!localpart) return res.status(400).json({ error: 'localpart required' });
    localpart = localpart.replace(/[^a-z0-9\-_.]/gi, '').toLowerCase();
    if (!password || password.length < 4) return res.status(400).json({ error: 'password min 4 chars' });
    const saltRounds = 10;
    const pw_hash = await bcrypt.hash(password, saltRounds);
    db.run('INSERT OR IGNORE INTO inboxes (localpart, pw_hash) VALUES (?,?)', [localpart, pw_hash], function(err) {
      if (err) return res.status(500).json({ error: 'db error' });
      if (this.changes === 0) return res.status(409).json({ error: 'inbox exists' });
      res.json({ localpart, address: `${localpart}@mail.05050101.xyz` });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// list messages (requires header X-INBOX-PW)
app.get('/api/messages/:localpart', async (req, res) => {
  const lp = req.params.localpart;
  const pw = req.header('X-INBOX-PW') || '';
  try {
    const ok = await verifyInboxPassword(lp, pw);
    if (!ok) return res.status(403).json({ error: 'forbidden' });
    db.all('SELECT id, sender, subject, created_at FROM messages WHERE localpart = ? ORDER BY created_at DESC LIMIT 500', [lp], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json(rows || []);
    });
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
});

// get single message
app.get('/api/message/:id', async (req, res) => {
  const id = req.params.id;
  const pw = req.header('X-INBOX-PW') || '';
  db.get('SELECT * FROM messages WHERE id = ?', [id], async (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(404).json({ error: 'not found' });
    const lp = row.localpart;
    try {
      const ok = await verifyInboxPassword(lp, pw);
      if (!ok) return res.status(403).json({ error: 'forbidden' });
      row.attachments = row.attachments ? JSON.parse(row.attachments) : [];
      res.json(row);
    } catch (e) {
      res.status(500).json({ error: 'server error' });
    }
  });
});

// SMTP server: accepts any RCPT TO and pipes to mailparser
const smtpServer = new SMTPServer({
  disabledCommands: ['AUTH'],
  logger: false,
  onData(stream, session, callback) {
    simpleParser(stream)
      .then(parsed => {
        try {
          // determine recipient localpart (take first recipient)
          let rcpt = (session.envelope && session.envelope.rcptTo && session.envelope.rcptTo[0] && session.envelope.rcptTo[0].address) || '';
          const localpart = rcpt.split('@')[0] || 'unknown';
          const attachments = [];
          if (parsed.attachments && parsed.attachments.length) {
            for (const a of parsed.attachments) {
              const fname = Date.now() + '-' + a.filename.replace(/[^a-z0-9_.-]/gi,'_');
              const fpath = path.join(ATTACH_DIR, fname);
              fs.writeFileSync(fpath, a.content);
              attachments.push({ filename: fname, originalname: a.filename, size: a.size, url: `/attachments/${encodeURIComponent(fname)}` });
            }
          }
          const msg = {
            localpart,
            sender: (parsed.from && parsed.from.text) || parsed.headers.get('from') || '',
            subject: parsed.subject || '',
            body_text: parsed.text || '',
            body_html: parsed.html || '',
            headers: JSON.stringify([...parsed.headers]),
            attachments: JSON.stringify(attachments)
          };
          db.run(`INSERT INTO messages (localpart, sender, subject, body_text, body_html, headers, attachments) VALUES (?,?,?,?,?,?,?)`,
            [msg.localpart, msg.sender, msg.subject, msg.body_text, msg.body_html, msg.headers, msg.attachments], function(err) {
              if (err) console.error('db insert err', err);
              else console.log('stored message id=', this.lastID, 'for', msg.localpart);
            });
        } catch (err) {
          console.error('parse/store err', err);
        }
        callback(null);
      })
      .catch(err => {
        console.error('mail parse err', err);
        callback(err);
      });
  },
  onMailFrom(address, session, callback) { return callback(); },
  onRcptTo(address, session, callback) { return callback(); }
});

smtpServer.listen(SMTP_PORT, () => {
  console.log('SMTP server listening on port', SMTP_PORT);
  console.log('Note: for public inbound delivery, point MX record to this host and ensure port 25/SMTP is reachable.');
});

// cleanup job: delete messages older than 30 days and remove attachments
cron.schedule('0 2 * * *', () => {
  console.log('Running daily cleanup job: deleting messages older than 30 days');
  db.all("SELECT id, attachments FROM messages WHERE created_at <= datetime('now','-30 days')", [], (err, rows) => {
    if (err) return console.error('cleanup db err', err);
    for (const r of rows) {
      try {
        const at = r.attachments ? JSON.parse(r.attachments) : [];
        for (const a of at) {
          const f = path.join(ATTACH_DIR, a.filename);
          if (fs.existsSync(f)) fs.unlinkSync(f);
        }
      } catch(e) { console.error('cleanup attach err', e); }
      db.run('DELETE FROM messages WHERE id = ?', [r.id]);
    }
  });
});

app.listen(PORT, () => {
  console.log('Web UI running on port', PORT);
  console.log('Create an inbox via POST /api/create {localpart, password}');
});
