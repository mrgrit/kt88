import json
import os
import sqlite3
import time
from pathlib import Path
from .security import password_hash, secret

ROOT = Path(os.environ.get('DATA_DIR', '/data'))

def connect():
    ROOT.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(ROOT / 'platform.sqlite', timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA foreign_keys=ON')
    return db

def init():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, must_change INTEGER DEFAULT 0, disabled INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, csrf TEXT, expires REAL);
        CREATE TABLE IF NOT EXISTS login_limits(key TEXT PRIMARY KEY, failures INTEGER, updated REAL);
        CREATE TABLE IF NOT EXISTS endpoints(id INTEGER PRIMARY KEY, name TEXT, domain TEXT UNIQUE, upstream TEXT, visibility TEXT, enabled INTEGER DEFAULT 1, created REAL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp REAL, actor TEXT, action TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, role TEXT, status TEXT, started REAL, finished REAL, result TEXT);
        CREATE TABLE IF NOT EXISTS proposals(id INTEGER PRIMARY KEY, kind TEXT, value TEXT, reason TEXT, status TEXT DEFAULT 'pending', actor TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS runtime_state(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS metrics(timestamp REAL, device TEXT, cpu REAL, memory INTEGER, rx REAL, tx REAL);
        CREATE INDEX IF NOT EXISTS metrics_device_time ON metrics(device,timestamp);
        ''')
        if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            password = secret('ADMIN_PASSWORD')
            if len(password) < 8:
                raise RuntimeError('ADMIN_PASSWORD_FILE with at least 8 characters is required')
            db.execute('INSERT INTO users(username,password,role,must_change) VALUES(?,?,?,?)',
                       (os.getenv('ADMIN_USER', 'admin'), password_hash(password), 'admin', int(os.getenv('ADMIN_MUST_CHANGE', '1'))))
        upstream = os.getenv('BOOTSTRAP_UPSTREAM')
        if upstream:
            db.execute('INSERT OR IGNORE INTO endpoints(name,domain,upstream,visibility,created) VALUES(?,?,?,?,?)',
                       ('Primary website', os.getenv('SITE_DOMAIN', 'example.internal'), upstream, os.getenv('SITE_VISIBILITY', 'internal'), time.time()))
            internal=os.getenv('INTERNAL_DOMAIN','platform.example.internal')
            db.execute('INSERT OR IGNORE INTO endpoints(name,domain,upstream,visibility,created) VALUES(?,?,?,?,?)',('Internal website',internal,upstream,'internal',time.time()))

def audit(actor, action, detail):
    with connect() as db:
        db.execute('INSERT INTO audit(timestamp,actor,action,detail) VALUES(?,?,?,?)',
                   (time.time(), actor, action, json.dumps(detail, ensure_ascii=False)))
