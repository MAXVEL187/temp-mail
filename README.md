# Temp-Mail (self-hosted)
This project provides a self-hosted disposable email inbox service.
Features:
- Accepts SMTP directly (built-in SMTP server) and stores messages into SQLite.
- Create password-protected inboxes: POST /api/create {localpart, password}
- View inbox by providing header X-INBOX-PW with the password (frontend does this)
- Automatic message expiry: messages older than 30 days are deleted daily (attachments removed)
- Simple web UI at / to create/open inboxes.

Notes:
- For public inbound email, point MX for mail.05050101.xyz to the host running the SMTP server and ensure port 25 (or your SMTP port) is reachable.
- If you cannot open port 25 from your network, deploy this on a VPS with a public IP, or use a mail relay that forwards to your SMTP.
- Cloudflare Tunnel does not reliably proxy SMTP/port 25; it can proxy HTTP for the web UI, but inbound SMTP requires a reachable SMTP endpoint. See docs/community threads for details.
