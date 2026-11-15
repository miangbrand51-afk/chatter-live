# Chatter Live — WhatsApp-inspired messaging starter

This project upgrades the static mockup into a small real-time web chat application.

## Included
- Username registration and sign-in
- Password hashing with bcrypt
- JWT authentication for HTTP and Socket.IO
- Live direct messages using Socket.IO
- SQLite database persistence
- People search and responsive mobile layout
- Basic security headers, request size limits, and rate limits

## Requirements
- Node.js 20 or newer
- npm

## Run locally

1. Extract the ZIP and open a terminal in the `chatter-live` folder.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Set a private JWT secret (at least 32 characters).

   macOS/Linux:
   ```bash
   export JWT_SECRET="$(openssl rand -hex 32)"
   ```

   Windows PowerShell:
   ```powershell
   $env:JWT_SECRET = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
   ```

4. Start the server:

   ```bash
   npm start
   ```

5. Open http://localhost:3000 in your browser.
6. Create two accounts (for example, in two different browsers or one normal and one private window) and start chatting.

The `chatter.sqlite` database is created automatically in this folder.

## Important limitations before public launch
This is a learning/starter app, not a production-ready WhatsApp replacement. Before exposing it to the public:
- Deploy behind HTTPS.
- Set a strong, private `JWT_SECRET`; never commit it or share it.
- Use secure, httpOnly cookies or a carefully reviewed token-storage design for production.
- Add account recovery, email/phone verification, blocking/reporting, abuse prevention, and moderation tools.
- Add pagination, message delivery/read receipts, file upload scanning, backups, and database migrations.
- Configure trusted origins/CORS and production logging.
- Consider PostgreSQL for multi-instance hosting; SQLite is suitable for a small single-server demo.
- Do not use this starter for sensitive or confidential communications. Messages are stored on the server and are not end-to-end encrypted.

## Project structure

```text
chatter-live/
  server.js
  package.json
  public/
    index.html
    style.css
    app.js
  README.md
```
