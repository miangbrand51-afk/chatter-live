const path = require("path");
const http = require("http");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET to a random secret of at least 32 characters before starting.");
  process.exit(1);
}

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database(process.env.DB_PATH || path.join(__dirname, "chatter.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id),
  recipient_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS messages_pair_idx ON messages(sender_id, recipient_id, id);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const messageLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false });

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
}
function getUserFromToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const user = getUserFromToken(token);
  if (!user) return res.status(401).json({ error: "Please sign in again." });
  req.user = user;
  next();
}
function validUsername(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_]{3,20}$/.test(value);
}

app.post("/api/register", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: "Username must be 3–20 characters: letters, numbers or underscore." });
  if (typeof password !== "string" || password.length < 8 || password.length > 72)
    return res.status(400).json({ error: "Password must be 8–72 characters." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
    const user = { id: Number(result.lastInsertRowid), username };
    res.status(201).json({ token: signToken(user), user });
  } catch (err) {
    if (String(err.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "That username is already taken." });
    console.error(err); res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "Enter your username and password." });
  const row = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE").get(username);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({ error: "Incorrect username or password." });
  const user = { id: row.id, username: row.username };
  res.json({ token: signToken(user), user });
});

app.get("/api/me", requireAuth, (req, res) => res.json({ user: { id: req.user.id, username: req.user.username } }));

app.get("/api/users", requireAuth, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username,
      (SELECT body FROM messages m
       WHERE (m.sender_id = u.id AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = u.id)
       ORDER BY m.id DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages m
       WHERE (m.sender_id = u.id AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = u.id)
       ORDER BY m.id DESC LIMIT 1) AS last_time
    FROM users u WHERE u.id != ?
    ORDER BY COALESCE(last_time, u.created_at) DESC, u.username COLLATE NOCASE
  `).all(req.user.id, req.user.id, req.user.id, req.user.id, req.user.id);
  res.json({ users });
});

app.get("/api/messages/:userId", requireAuth, (req, res) => {
  const otherId = Number(req.params.userId);
  if (!Number.isInteger(otherId) || otherId < 1 || otherId === req.user.id) return res.status(400).json({ error: "Invalid conversation." });
  const other = db.prepare("SELECT id FROM users WHERE id = ?").get(otherId);
  if (!other) return res.status(404).json({ error: "User not found." });
  const messages = db.prepare(`
    SELECT id, sender_id AS senderId, recipient_id AS recipientId, body, created_at AS createdAt
    FROM messages
    WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
    ORDER BY id ASC LIMIT 500
  `).all(req.user.id, otherId, otherId, req.user.id);
  res.json({ messages });
});

app.post("/api/messages", requireAuth, messageLimiter, (req, res) => {
  const { recipientId, body } = req.body || {};
  const target = Number(recipientId);
  if (!Number.isInteger(target) || target < 1 || target === req.user.id) return res.status(400).json({ error: "Choose a valid recipient." });
  if (typeof body !== "string" || !body.trim() || body.length > 2000) return res.status(400).json({ error: "Message must be 1–2000 characters." });
  const recipient = db.prepare("SELECT id FROM users WHERE id = ?").get(target);
  if (!recipient) return res.status(404).json({ error: "Recipient not found." });
  const result = db.prepare("INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)").run(req.user.id, target, body.trim());
  const message = db.prepare("SELECT id, sender_id AS senderId, recipient_id AS recipientId, body, created_at AS createdAt FROM messages WHERE id = ?").get(result.lastInsertRowid);
  io.to(`user:${target}`).emit("message:new", message);
  io.to(`user:${req.user.id}`).emit("message:sent", message);
  res.status(201).json({ message });
});

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  const user = token && getUserFromToken(token);
  if (!user) return next(new Error("Unauthorized"));
  socket.user = user;
  next();
});
io.on("connection", socket => {
  socket.join(`user:${socket.user.id}`);
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
server.listen(PORT, () => console.log(`Chatter is running at http://localhost:${PORT}`));
