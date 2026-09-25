"""Models layer: connection, schema and starting data.
Uses SQLite locally (python app.py) and PostgreSQL when DATABASE_URL is set (e.g. on Render)."""
import os, sqlite3
from flask import g
from werkzeug.security import generate_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL", "")
PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
DB_PATH = os.environ.get("DATABASE_PATH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "tasks.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id {PK}, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('manager','employee')), department TEXT, active INTEGER NOT NULL DEFAULT 1, email TEXT);
CREATE TABLE IF NOT EXISTS tasks(id {PK}, title TEXT NOT NULL, description TEXT,
  assignee_id INTEGER NOT NULL REFERENCES users(id), created_by INTEGER REFERENCES users(id),
  priority TEXT NOT NULL DEFAULT 'Medium', status TEXT NOT NULL DEFAULT 'Pending', progress INTEGER NOT NULL DEFAULT 0,
  deadline TEXT NOT NULL, created_at TEXT DEFAULT {NOW}, completed_at TEXT);
CREATE TABLE IF NOT EXISTS comments(id {PK}, task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT DEFAULT {NOW});
CREATE TABLE IF NOT EXISTS daily_updates(id {PK}, user_id INTEGER NOT NULL REFERENCES users(id),
  update_date TEXT NOT NULL, worked_on TEXT, completed TEXT, in_progress TEXT, blockers TEXT,
  created_at TEXT DEFAULT {NOW}, UNIQUE(user_id, update_date));
CREATE TABLE IF NOT EXISTS activity(id {PK}, task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, details TEXT, created_at TEXT DEFAULT {NOW});
CREATE TABLE IF NOT EXISTS login_codes(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files(id {PK}, task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id), filename TEXT NOT NULL, size INTEGER NOT NULL, stage TEXT,
  data {BLOB} NOT NULL, created_at TEXT DEFAULT {NOW});
""".replace("{BLOB}", "BYTEA" if PG else "BLOB").replace("{PK}", "SERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY").replace(
    "{NOW}", "to_char(now(),'YYYY-MM-DD HH24:MI:SS')" if PG else "(datetime('now','localtime'))")

def _connect():
    if PG:
        import psycopg2, psycopg2.extras
        return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; c.execute("PRAGMA foreign_keys=ON")
    return c

def _sql(sql):  # queries are written with ? placeholders; PostgreSQL wants %s
    return sql.replace("?", "%s") if PG else sql

def blob(b):
    if PG:
        import psycopg2
        return psycopg2.Binary(b)
    return b

def get_db():
    if "db" not in g: g.db = _connect()
    return g.db

def close_db(_=None):
    d = g.pop("db", None)
    if d: d.close()

def query(sql, args=(), one=False):
    cur = get_db().cursor(); cur.execute(_sql(sql), args); rows = cur.fetchall(); cur.close()
    return (rows[0] if rows else None) if one else rows

def execute(sql, args=(), returning=True):
    """returning=False for inserts into tables with no auto id column (e.g. login_codes)."""
    d = get_db(); cur = d.cursor(); ins = returning and PG and sql.lstrip().upper().startswith("INSERT")
    cur.execute(_sql(sql) + (" RETURNING id" if ins else ""), args)
    new = (cur.fetchone() or {}).get("id") if ins else (cur.lastrowid if returning else None)
    cur.close(); d.commit(); return new

def log(task_id, user_id, action, details=""):
    execute("INSERT INTO activity(task_id,user_id,action,details) VALUES(?,?,?,?)", (task_id, user_id, action, details))

def init_db():
    c = _connect(); cur = c.cursor()
    if PG:
        cur.execute(SCHEMA)
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT")
    else:
        cur.executescript(SCHEMA)
        cols = [r[1] for r in cur.execute("PRAGMA table_info(users)").fetchall()]
        for col, ddl in (("active", "INTEGER NOT NULL DEFAULT 1"), ("email", "TEXT")):
            if col not in cols: cur.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users(email)")
    cur.execute("SELECT 1 FROM users LIMIT 1")
    if not cur.fetchone(): seed(cur)
    c.commit(); c.close()

def seed(cur):
    """Creates one manager account. Set ADMIN_USERNAME / ADMIN_PASSWORD / ADMIN_NAME to change it."""
    cur.execute(_sql("INSERT INTO users(name,username,email,password_hash,role,department) VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO NOTHING"),
                (os.environ.get("ADMIN_NAME", "Administrator"), os.environ.get("ADMIN_USERNAME", "admin").lower(), os.environ.get("ADMIN_EMAIL", "admin@company.com").lower(),
                 generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123")), "manager", "Management"))
