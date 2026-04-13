require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");


const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-key-change-in-production"; // Put in .env later

const allowedOrigins = (
  process.env.CORS_ORIGIN ||
  "http://localhost:3000,http://127.0.0.1:3000"
)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({ origin: allowedOrigins }));
app.use(express.json());

// Helper functions
function toSqlDate(lastModified) {
  if (lastModified == null) return null;
  const mysqlDateTimeRe = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;

  if (typeof lastModified === "string" && mysqlDateTimeRe.test(lastModified)) {
    return lastModified;
  }

  const d = typeof lastModified === "number" ? new Date(lastModified) : new Date(String(lastModified));
  if (Number.isNaN(d.getTime())) return null;

  const pad2 = (n) => String(n).padStart(2, "0");
  const yyyy = d.getFullYear();
  const MM = pad2(d.getMonth() + 1);
  const DD = pad2(d.getDate());
  const hh = pad2(d.getHours());
  const mm = pad2(d.getMinutes());
  const ss = pad2(d.getSeconds());
  return `${yyyy}-${MM}-${DD} ${hh}:${mm}:${ss}`;
}

function normalizeSqlForMySql(sql) {
  return sql
    .replace(/\$(\d+)/g, "?")
    .replace(/"([A-Za-z0-9_]+)"/g, "`$1`");
}

function lastModifiedFromRow(value) {
  if (value == null) return Date.now();
  if (value instanceof Date) return value.getTime();
  const parsed = Date.parse(value);
  if (!Number.isNaN(parsed)) return parsed;
  return Date.now();
}

function noteRowToClient(row) {
  return {
    id: row.id,
    title: row.title,
    body: row.body,
    lastModified: lastModifiedFromRow(row.lastModified),
    owner_id: row.owner_id ?? null,
  };
}

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    req.user = null;
    next();
  }
}

let pool;

async function dbQuery(sql, params = []) {
  const normalizedSql = normalizeSqlForMySql(sql);
  const [result] = await pool.query(normalizedSql, params);
  if (Array.isArray(result)) {
    return { rows: result, rowCount: result.length };
  }
  return { rows: [], rowCount: result?.affectedRows ?? 0 };
}

async function getNoteRoleForUser(noteId, userId) {
  if (!userId) return "viewer";
  const { rows } = await dbQuery("SELECT owner_id FROM notes WHERE id = $1", [noteId]);
  if (rows.length === 0) return null;
  if (rows[0].owner_id === userId) return "owner";
  const { rows: editors } = await dbQuery(
    "SELECT 1 AS x FROM note_editors WHERE note_id = $1 AND user_ID = $2 LIMIT 1",
    [noteId, userId]
  );
  if (editors.length > 0) return "editor";
  return "viewer";
}

async function canEditNote(noteId, userId) {
  const r = await getNoteRoleForUser(noteId, userId);
  return r === "owner" || r === "editor";
}

async function isNoteOwner(noteId, userId) {
  if (!userId) return false;
  const { rows } = await dbQuery("SELECT owner_id FROM notes WHERE id = $1", [noteId]);
  return rows.length > 0 && rows[0].owner_id === userId;
}

async function listPendingEditorRequests(noteId) {
  const { rows } = await dbQuery(
    `SELECT r.id, r.requester_user_ID, r.created_at, u.first_name, u.last_name, u.email
     FROM note_editor_requests r
     INNER JOIN users u ON u.user_ID = r.requester_user_ID
     WHERE r.note_id = $1 AND r.status = 'pending'
     ORDER BY r.created_at ASC`,
    [noteId]
  );
  return rows.map((row) => {
    let createdMs =
      row.created_at instanceof Date
        ? row.created_at.getTime()
        : Date.parse(String(row.created_at));
    if (Number.isNaN(createdMs)) createdMs = Date.now();
    return {
      id: row.id,
      requester_user_ID: row.requester_user_ID,
      created_at: createdMs,
      first_name: row.first_name,
      last_name: row.last_name,
      email: row.email,
    };
  });
}

// Database setup + server start
(async () => {
  const databaseUrl = process.env.DATABASE_URL || process.env.DB_URL;

  try {
    console.log("⏳ Connecting to MySQL...");
    if (!databaseUrl) {
      throw new Error("Missing DATABASE_URL (or DB_URL) in environment");
    }

    const parsed = new URL(databaseUrl);
    const requireSsl = (parsed.searchParams.get("ssl-mode") || "").toUpperCase() === "REQUIRED";
    parsed.searchParams.delete("ssl-mode");

    const rejectUnauthorized =
      String(process.env.DB_SSL_REJECT_UNAUTHORIZED ?? "false").toLowerCase() === "true";
    if (requireSsl && !rejectUnauthorized) {
      console.log(
        "⚠️ MySQL SSL: rejectUnauthorized=false (allows self-signed certificates)"
      );
    }
    pool = mysql.createPool({
      uri: parsed.toString(),
      ...(requireSsl ? { ssl: { rejectUnauthorized } } : {}),
    });

    await dbQuery("SELECT 1");
    console.log(" Connected to MySQL");

    // Create table if it doesn't exist
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS notes (
        id VARCHAR(255) PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        lastModified DATETIME NOT NULL
      )
    `);
    console.log(" Notes table ready");

    // Best-effort migration: ensure notes.lastModified is DATETIME.
    // If an older schema stored it as INT/VARCHAR, the seed insert can fail with "Data truncated".
    try {
      await dbQuery(
        "UPDATE notes SET lastModified = FROM_UNIXTIME(CAST(lastModified AS UNSIGNED)/1000) WHERE CAST(lastModified AS CHAR) REGEXP '^[0-9]{11,}$'"
      );
    } catch (err) {
      // Ignore; we'll still try to coerce the column type below.
    }
    try {
      await dbQuery("ALTER TABLE notes MODIFY lastModified DATETIME NOT NULL");
    } catch (err) {
      // If it already matches, ALTER will succeed or fail safely depending on existing data.
    }

    // Automatic seeding
    const sampleNotes = [
      { id: "uuid-001", title: "store procedure", body: "syntax", lastModified: "2026-03-18 23:31:28" },
      { id: "uuid-002", title: "function", body: "syntax", lastModified: "2026-03-18 23:31:45" },
      { id: "uuid-003", title: "query", body: "syntax", lastModified: "2026-03-18 23:31:57" },
    ];

    for (const note of sampleNotes) {
      await dbQuery(
        'INSERT INTO notes (id, title, body, "lastModified") VALUES ($1, $2, $3, $4) ON DUPLICATE KEY UPDATE id = id',
        [note.id, note.title, note.body, toSqlDate(note.lastModified)]
      );
    }
    console.log("Sample notes seeded");

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS comments (
        id VARCHAR(255) PRIMARY KEY,
        userId VARCHAR(191) NOT NULL,
        noteId VARCHAR(191) NOT NULL,
        body TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        replyTo VARCHAR(191) DEFAULT NULL,
        FOREIGN KEY (noteId) REFERENCES notes(id) ON DELETE CASCADE,
        FOREIGN KEY (replyTo) REFERENCES comments(id) ON DELETE SET NULL
      )
    `);
    console.log("Comments table ready");

    //// INITIALIZE USER TABLE ////
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS users (
        user_ID VARCHAR(191) PRIMARY KEY,
        first_name VARCHAR(191) NOT NULL,
        last_name VARCHAR(191) NOT NULL,
        email VARCHAR(191) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        position VARCHAR(19142) NOT NULL,
        major_department VARCHAR(191) NOT NULL,
        permission_access VARCHAR(191) NOT NULL DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("Users table ready");

    // Migrate older schemas (id → user_ID, permission_access, major_department)
    try {
      await dbQuery("ALTER TABLE notes DROP FOREIGN KEY fk_notes_owner_id");
    } catch (err) {
      if (err.errno !== 1091 && err.code !== "ER_CANT_DROP_FIELD_OR_KEY") throw err;
    }
    try {
      await dbQuery("ALTER TABLE users CHANGE COLUMN id user_ID VARCHAR(191) NOT NULL");
    } catch (err) {
      if (err.errno !== 1054) throw err;
    }
    try {
      await dbQuery(
        "ALTER TABLE users ADD COLUMN permission_access VARCHAR(191) NOT NULL DEFAULT 'user'"
      );
    } catch (err) {
      if (err.code !== "ER_DUP_FIELDNAME") throw err;
    }
    try {
      await dbQuery(
        "ALTER TABLE users ADD COLUMN major_department VARCHAR(191) NOT NULL DEFAULT ''"
      );
    } catch (err) {
      if (err.code !== "ER_DUP_FIELDNAME") throw err;
    }

    try {
      await dbQuery("ALTER TABLE notes ADD COLUMN owner_id VARCHAR(191) DEFAULT NULL");
    } catch (err) {
      if (err.code !== "ER_DUP_FIELDNAME") throw err;
    }

    try {
      await dbQuery(
        "ALTER TABLE notes ADD CONSTRAINT fk_notes_owner_id FOREIGN KEY (owner_id) REFERENCES users(user_ID) ON DELETE SET NULL"
      );
    } catch (err) {
      if (err.code !== "ER_DUP_KEYNAME" && err.errno !== 1826) throw err;
    }
    console.log("Notes owner_id column ready");

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS note_editors (
        note_id VARCHAR(255) NOT NULL,
        user_ID VARCHAR(191) NOT NULL,
        PRIMARY KEY (note_id, user_ID),
        CONSTRAINT fk_note_editors_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
        CONSTRAINT fk_note_editors_user FOREIGN KEY (user_ID) REFERENCES users(user_ID) ON DELETE CASCADE
      )
    `);
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS note_editor_requests (
        id VARCHAR(191) PRIMARY KEY,
        note_id VARCHAR(255) NOT NULL,
        requester_user_ID VARCHAR(191) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_ner_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
        CONSTRAINT fk_ner_user FOREIGN KEY (requester_user_ID) REFERENCES users(user_ID) ON DELETE CASCADE,
        INDEX idx_ner_note_status_created (note_id, status, created_at)
      )
    `);
    console.log("Note permission tables ready");

    // Pending editor-request tracking (log + procedure for owners)
    try {
      await dbQuery(`
      CREATE TABLE IF NOT EXISTS note_editor_request_pending_log (
        log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        request_id VARCHAR(191) NOT NULL,
        note_id VARCHAR(255) NOT NULL,
        requester_user_ID VARCHAR(191) NOT NULL,
        logged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_note_editor_request_pending_log_request (request_id),
        KEY idx_note_editor_request_pending_log_note (note_id),
        CONSTRAINT fk_nerpl_note FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
        CONSTRAINT fk_nerpl_user FOREIGN KEY (requester_user_ID) REFERENCES users(user_ID) ON DELETE CASCADE
      )
    `);
    } catch (err) {
      console.warn("⚠️ note_editor_request_pending_log:", err.message);
    }

    try {
      await dbQuery("DROP TRIGGER IF EXISTS tr_note_editor_requests_after_insert_pending");
      await dbQuery(`
      CREATE TRIGGER tr_note_editor_requests_after_insert_pending
      AFTER INSERT ON note_editor_requests
      FOR EACH ROW
      BEGIN
        IF NEW.status = 'pending' THEN
          INSERT INTO note_editor_request_pending_log (request_id, note_id, requester_user_ID)
          VALUES (NEW.id, NEW.note_id, NEW.requester_user_ID)
          ON DUPLICATE KEY UPDATE logged_at = CURRENT_TIMESTAMP;
        END IF;
      END
    `);
    } catch (err) {
      console.warn("⚠️ Editor-request pending trigger:", err.message);
    }

    try {
      await dbQuery("DROP PROCEDURE IF EXISTS sp_list_pending_editor_requests_for_owned_notes");
      await dbQuery(`
      CREATE PROCEDURE sp_list_pending_editor_requests_for_owned_notes (IN p_owner_user_ID VARCHAR(191))
      BEGIN
        SELECT
          r.id AS request_id,
          r.note_id,
          r.requester_user_ID,
          r.created_at,
          u.first_name,
          u.last_name,
          u.email,
          n.title AS note_title
        FROM note_editor_requests r
        INNER JOIN notes n ON n.id = r.note_id
        INNER JOIN users u ON u.user_ID = r.requester_user_ID
        WHERE n.owner_id = p_owner_user_ID
          AND r.status = 'pending'
        ORDER BY r.created_at ASC;
      END
    `);
    } catch (err) {
      console.warn("⚠️ sp_list_pending_editor_requests_for_owned_notes:", err.message);
    }

    try {
      await dbQuery("DROP PROCEDURE IF EXISTS sp_list_pending_editor_request_log_for_owned_notes");
      await dbQuery(`
      CREATE PROCEDURE sp_list_pending_editor_request_log_for_owned_notes (IN p_owner_user_ID VARCHAR(191))
      BEGIN
        SELECT
          l.log_id,
          l.request_id,
          l.note_id,
          l.requester_user_ID,
          l.logged_at,
          IFNULL(r.status, '(deleted)') AS request_status,
          n.title AS note_title
        FROM note_editor_request_pending_log l
        INNER JOIN notes n ON n.id = l.note_id
        LEFT JOIN note_editor_requests r ON r.id = l.request_id
        WHERE n.owner_id = p_owner_user_ID
        ORDER BY l.logged_at ASC;
      END
    `);
    } catch (err) {
      console.warn(" sp_list_pending_editor_request_log_for_owned_notes:", err.message);
    }

    // Start server on port 5001
    const port = process.env.PORT || 5001;
    app.listen(port, () => {
      console.log(` Server running on http://localhost:${port}`);
    });

  } catch (err) {
    console.error("Startup error:", err.message);
    process.exit(1);
  }
})();

// ====================== ROUTES ======================

app.get("/api/notes", async (req, res) => {
  try {
    const { rows } = await dbQuery('SELECT * FROM notes ORDER BY "lastModified" DESC');
    res.json(rows.map(noteRowToClient));
  } catch (err) {
    console.error("GET /api/notes error:", err.message);
    res.status(500).json({ error: "Failed to fetch notes" });
  }
});

app.get("/api/notes/:noteId/access", optionalAuth, async (req, res) => {
  try {
    const noteId = req.params.noteId;
    const userId = req.user?.userId ?? null;
    const { rows } = await dbQuery("SELECT owner_id FROM notes WHERE id = $1", [noteId]);
    if (rows.length === 0) return res.status(404).json({ error: "Note not found" });
    const ownerId = rows[0].owner_id;
    const role = await getNoteRoleForUser(noteId, userId);

    let pendingRequests = [];
    if (role === "owner") {
      pendingRequests = await listPendingEditorRequests(noteId);
    }

    let pendingMyRequest = false;
    if (userId && role === "viewer") {
      const pr = await dbQuery(
        `SELECT id FROM note_editor_requests WHERE note_id = $1 AND requester_user_ID = $2 AND status = 'pending' LIMIT 1`,
        [noteId, userId]
      );
      pendingMyRequest = pr.rows.length > 0;
    }

    const canRequestEditor =
      role === "viewer" && !!userId && !!ownerId && !pendingMyRequest;

    res.json({
      role,
      noteHasOwner: !!ownerId,
      pendingRequests,
      pendingMyRequest,
      canRequestEditor,
    });
  } catch (err) {
    console.error("GET /api/notes/:noteId/access error:", err.message);
    res.status(500).json({ error: "Failed to load note access" });
  }
});

app.post("/api/notes/:noteId/editor-requests", verifyToken, async (req, res) => {
  try {
    const noteId = req.params.noteId;
    const requesterId = req.user.userId;
    const role = await getNoteRoleForUser(noteId, requesterId);
    if (role !== "viewer") {
      return res.status(400).json({ error: "Only viewers can request editor access" });
    }
    const { rows } = await dbQuery("SELECT owner_id FROM notes WHERE id = $1", [noteId]);
    if (rows.length === 0) return res.status(404).json({ error: "Note not found" });
    if (!rows[0].owner_id) {
      return res.status(400).json({ error: "This note has no owner; editor requests are not available." });
    }
    const existing = await dbQuery(
      `SELECT id FROM note_editor_requests WHERE note_id = $1 AND requester_user_ID = $2 AND status = 'pending' LIMIT 1`,
      [noteId, requesterId]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "You already have a pending request" });
    }
    const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    await dbQuery(
      `INSERT INTO note_editor_requests (id, note_id, requester_user_ID, status) VALUES ($1, $2, $3, 'pending')`,
      [requestId, noteId, requesterId]
    );
    res.status(201).json({ id: requestId, message: "Request sent" });
  } catch (err) {
    console.error("POST editor-request error:", err.message);
    res.status(500).json({ error: "Failed to submit request" });
  }
});

app.post(
  "/api/notes/:noteId/editor-requests/:requestId/accept",
  verifyToken,
  async (req, res) => {
    try {
      const { noteId, requestId } = req.params;
      const userId = req.user.userId;
      if (!(await isNoteOwner(noteId, userId))) {
        return res.status(403).json({ error: "Only the note owner can accept requests" });
      }
      const { rows } = await dbQuery(
        `SELECT requester_user_ID, status FROM note_editor_requests WHERE id = $1 AND note_id = $2 LIMIT 1`,
        [requestId, noteId]
      );
      if (rows.length === 0) return res.status(404).json({ error: "Request not found" });
      if (rows[0].status !== "pending") {
        return res.status(400).json({ error: "This request is no longer pending" });
      }
      const requester = rows[0].requester_user_ID;
      await dbQuery(
        `INSERT INTO note_editors (note_id, user_ID) VALUES ($1, $2) ON DUPLICATE KEY UPDATE user_ID = user_ID`,
        [noteId, requester]
      );
      await dbQuery(`UPDATE note_editor_requests SET status = 'accepted' WHERE id = $1`, [requestId]);
      res.json({ message: "Editor access granted" });
    } catch (err) {
      console.error("Accept editor-request error:", err.message);
      res.status(500).json({ error: "Failed to accept request" });
    }
  }
);

app.post(
  "/api/notes/:noteId/editor-requests/:requestId/reject",
  verifyToken,
  async (req, res) => {
    try {
      const { noteId, requestId } = req.params;
      const userId = req.user.userId;
      if (!(await isNoteOwner(noteId, userId))) {
        return res.status(403).json({ error: "Only the note owner can reject requests" });
      }
      const { rows } = await dbQuery(
        `SELECT status FROM note_editor_requests WHERE id = $1 AND note_id = $2 LIMIT 1`,
        [requestId, noteId]
      );
      if (rows.length === 0) return res.status(404).json({ error: "Request not found" });
      if (rows[0].status !== "pending") {
        return res.status(400).json({ error: "This request is no longer pending" });
      }
      await dbQuery(`UPDATE note_editor_requests SET status = 'rejected' WHERE id = $1`, [requestId]);
      res.json({ message: "Request rejected" });
    } catch (err) {
      console.error("Reject editor-request error:", err.message);
      res.status(500).json({ error: "Failed to reject request" });
    }
  }
);

app.get("/api/notes/:id", async (req, res) => {
  try {
    const { rows } = await dbQuery("SELECT * FROM notes WHERE id = $1", [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Note not found" });
    res.json(noteRowToClient(rows[0]));
  } catch (err) {
    console.error("GET /api/notes/:id error:", err.message);
    res.status(500).json({ error: "Failed to fetch note" });
  }
});

app.post("/api/notes", verifyToken, async (req, res) => {
  try {
    const { id, title, body, lastModified } = req.body;
    if (!id || body === undefined || lastModified == null) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const titleStr = title ?? "";
    const dt = toSqlDate(lastModified);
    if (!dt) {
      return res.status(400).json({ error: "Invalid lastModified" });
    }

    const ownerId = req.user.userId;

    await dbQuery(
      'INSERT INTO notes (id, title, body, "lastModified", owner_id) VALUES ($1, $2, $3, $4, $5)',
      [id, titleStr, body, dt, ownerId]
    );

    const echoMs = typeof lastModified === "number" ? lastModified : Date.now();
    res.status(201).json({ id, title: titleStr, body, lastModified: echoMs, owner_id: ownerId });
  } catch (err) {
    console.error("POST /api/notes error:", err.message);
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Note with this ID already exists" });
    }
    res.status(500).json({ error: "Failed to create note" });
  }
});

app.put("/api/notes/:id", verifyToken, async (req, res) => {
  try {
    const noteId = req.params.id;
    const userId = req.user.userId;
    if (!(await canEditNote(noteId, userId))) {
      return res.status(403).json({ error: "You do not have permission to edit this note" });
    }

    const { title, body, lastModified } = req.body;
    if (title === undefined || body === undefined || lastModified == null) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const titleStr = title ?? "";
    const dt = toSqlDate(lastModified);
    if (!dt) {
      return res.status(400).json({ error: "Invalid lastModified" });
    }

    const result = await dbQuery(
      'UPDATE notes SET title = $1, body = $2, "lastModified" = $3 WHERE id = $4',
      [titleStr, body, dt, noteId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Note not found" });
    }

    const echoMs = typeof lastModified === "number" ? lastModified : Date.now();
    res.json({ id: noteId, title: titleStr, body, lastModified: echoMs });
  } catch (err) {
    console.error("PUT /api/notes/:id error:", err.message);
    res.status(500).json({ error: "Failed to update note" });
  }
});

app.delete("/api/notes/:id", verifyToken, async (req, res) => {
  try {
    const noteId = req.params.id;
    const userId = req.user.userId;
    if (!(await isNoteOwner(noteId, userId))) {
      return res.status(403).json({ error: "Only the note owner can delete this note" });
    }

    const result = await dbQuery("DELETE FROM notes WHERE id = $1", [noteId]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Note not found" });
    }
    res.json({ message: "Note deleted" });
  } catch (err) {
    console.error("DELETE /api/notes/:id error:", err.message);
    res.status(500).json({ error: "Failed to delete note" });
  }
});




// ====================== AUTH API ======================

// Register new user
app.post("/api/auth/register", async (req, res) => {
  try {
    const { first_name, last_name, email, password, position, major_department, permission_access } =
      req.body;

    if (!first_name || !last_name || !email || !password || !position || !major_department) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existing = await dbQuery("SELECT user_ID FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "User with this email already exists" });
    }

    const user_ID = `user-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);
    const perm =
      permission_access && String(permission_access).trim()
        ? String(permission_access).trim()
        : "user";

    await dbQuery(
      `INSERT INTO users (user_ID, first_name, last_name, email, password_hash, position, major_department, permission_access)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        user_ID,
        first_name,
        last_name,
        email.toLowerCase(),
        password_hash,
        position,
        String(major_department).trim(),
        perm,
      ]
    );

    res.status(201).json({ message: "Account created successfully" });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ error: "Failed to create account" });
  }
});

// Login user
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const { rows } = await dbQuery(
      "SELECT * FROM users WHERE email = $1",
      [email.toLowerCase()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: user.user_ID, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        user_ID: user.user_ID,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        position: user.position,
        permission_access: user.permission_access,
        major_department: user.major_department,
        created_at: user.created_at instanceof Date ? user.created_at.getTime() : Date.now(),
      }
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

// ====================== COMMENTS API ======================

/**
* GET all comments for a specific note (flat list, ordered by creation time)
*/
app.get("/api/notes/:noteId/comments", async (req, res) => {
try {
const { rows } = await dbQuery(
`SELECT * FROM comments 
 WHERE "noteId" = $1 
 ORDER BY "createdAt" ASC`,
[req.params.noteId]
);

const comments = rows.map(row => ({
id: row.id,
userId: row.userId,
noteId: row.noteId,
body: row.body,
createdAt: row.createdAt instanceof Date ? row.createdAt.getTime() : Date.now(),
replyTo: row.replyTo || null,
}));

res.json(comments);
} catch (err) {
console.error("GET /api/notes/:noteId/comments error:", err.message);
res.status(500).json({ error: "Failed to fetch comments" });
}
});

/**
* POST a new comment (main comment or reply)
*/
app.post("/api/notes/:noteId/comments", async (req, res) => {
try {
const { id, userId, body, replyTo } = req.body;

if (!id || !body || body.trim() === "") {
return res.status(400).json({ error: "Missing required fields" });
}

const finalUserId = userId || "demo-user";
const now = new Date();

await dbQuery(
`INSERT INTO comments (id, "userId", "noteId", body, "createdAt", "replyTo")
 VALUES ($1, $2, $3, $4, $5, $6)`,
[id, finalUserId, req.params.noteId, body.trim(), now, replyTo || null]
);

res.status(201).json({
id,
userId: finalUserId,
noteId: req.params.noteId,
body: body.trim(),
createdAt: now.getTime(),
replyTo: replyTo || null,
});
} catch (err) {
console.error("POST comment error:", err.message);
res.status(500).json({ error: "Failed to create comment" });
}
})