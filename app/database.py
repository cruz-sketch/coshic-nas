import sqlite3
import json
import os

DB_PATH = os.environ.get('CONFIG_DIR', '/data/config') + '/nas.db'


class Database:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        return conn

    def _init_db(self):
        with self._conn() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS shares (
                    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                    name                  TEXT UNIQUE NOT NULL,
                    path                  TEXT NOT NULL,
                    comment               TEXT DEFAULT '',
                    protocols             TEXT DEFAULT '[]',
                    public                INTEGER DEFAULT 0,
                    smb_guest_write       INTEGER DEFAULT 0,
                    nfs_hosts             TEXT DEFAULT '*',
                    nfs_options           TEXT DEFAULT 'rw,sync,no_subtree_check,root_squash',
                    access_list           TEXT DEFAULT '[]',
                    timemachine           INTEGER DEFAULT 0,
                    smb_async_io          INTEGER DEFAULT 1,
                    smb_sync_writes       INTEGER DEFAULT 0,
                    webdav_inline_preview INTEGER DEFAULT 1,
                    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS users (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    username   TEXT UNIQUE NOT NULL,
                    enabled    INTEGER DEFAULT 1,
                    readonly   INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    actor       TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    target      TEXT DEFAULT '',
                    details     TEXT DEFAULT '',
                    remote_addr TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_audit_log_ts     ON audit_log(ts);
                CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
            ''')
            # migrations for existing DBs (silently skip if column already exists)
            for migration in (
                'ALTER TABLE users ADD COLUMN readonly INTEGER DEFAULT 0',
                'ALTER TABLE shares ADD COLUMN timemachine INTEGER DEFAULT 0',
                'ALTER TABLE shares ADD COLUMN smb_guest_write INTEGER DEFAULT 0',
                'ALTER TABLE shares ADD COLUMN smb_async_io INTEGER DEFAULT 1',
                'ALTER TABLE shares ADD COLUMN smb_sync_writes INTEGER DEFAULT 0',
                'ALTER TABLE shares ADD COLUMN webdav_inline_preview INTEGER DEFAULT 1',
            ):
                try:
                    c.execute(migration)
                except sqlite3.OperationalError:
                    # "duplicate column name" - already migrated
                    pass

    # ---- Shares ----

    def get_all_shares(self):
        with self._conn() as c:
            return [dict(r) for r in c.execute('SELECT * FROM shares ORDER BY name')]

    def get_share(self, share_id):
        with self._conn() as c:
            r = c.execute('SELECT * FROM shares WHERE id = ?', (share_id,)).fetchone()
            return dict(r) if r else None

    def create_share(self, data):
        with self._conn() as c:
            c.execute(
                '''INSERT INTO shares (name, path, comment, protocols, public, smb_guest_write,
                   nfs_hosts, nfs_options, access_list, timemachine, smb_async_io, smb_sync_writes,
                   webdav_inline_preview)
                   VALUES (:name, :path, :comment, :protocols, :public, :smb_guest_write,
                   :nfs_hosts, :nfs_options, :access_list, :timemachine,
                   :smb_async_io, :smb_sync_writes, :webdav_inline_preview)''',
                data
            )

    def update_share(self, share_id, data):
        with self._conn() as c:
            c.execute(
                '''UPDATE shares SET name=:name, path=:path, comment=:comment,
                   protocols=:protocols, public=:public, smb_guest_write=:smb_guest_write,
                   nfs_hosts=:nfs_hosts, nfs_options=:nfs_options,
                   access_list=:access_list, timemachine=:timemachine,
                   smb_async_io=:smb_async_io, smb_sync_writes=:smb_sync_writes,
                   webdav_inline_preview=:webdav_inline_preview
                   WHERE id=:id''',
                {**data, 'id': share_id}
            )

    def delete_share(self, share_id):
        with self._conn() as c:
            c.execute('DELETE FROM shares WHERE id = ?', (share_id,))

    # ---- Users ----

    def get_all_users(self):
        with self._conn() as c:
            return [dict(r) for r in c.execute('SELECT * FROM users ORDER BY username')]

    def get_user(self, user_id):
        with self._conn() as c:
            r = c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            return dict(r) if r else None

    def create_user(self, username, readonly=False):
        with self._conn() as c:
            c.execute('INSERT INTO users (username, readonly) VALUES (?, ?)',
                      (username, 1 if readonly else 0))

    def update_user(self, user_id, enabled, readonly=False):
        with self._conn() as c:
            c.execute('UPDATE users SET enabled=?, readonly=? WHERE id=?',
                      (1 if enabled else 0, 1 if readonly else 0, user_id))

    def delete_user(self, user_id):
        with self._conn() as c:
            c.execute('DELETE FROM users WHERE id = ?', (user_id,))

    # ---- Stats ----

    def get_stats(self):
        with self._conn() as c:
            shares = c.execute('SELECT COUNT(*) FROM shares').fetchone()[0]
            users  = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        return {'shares': shares, 'users': users}

    # ---- Audit log ----

    # Hard cap on retained rows. Pruned on every insert (cheap with the index).
    AUDIT_MAX_ROWS = 10000

    def log_audit(self, actor, action, target='', details='', remote_addr=''):
        """Append a row. `details` may be a dict/list - it's JSON-encoded."""
        if isinstance(details, (dict, list)):
            details = json.dumps(details, separators=(',', ':'), ensure_ascii=False)
        actor       = (actor       or '')[:64]
        action      = (action      or '')[:64]
        target      = (target      or '')[:128]
        details     = (details     or '')[:512]
        remote_addr = (remote_addr or '')[:64]
        with self._conn() as c:
            c.execute(
                'INSERT INTO audit_log (actor, action, target, details, remote_addr) '
                'VALUES (?, ?, ?, ?, ?)',
                (actor, action, target, details, remote_addr)
            )
            # Trim oldest rows beyond the cap. SQLite supports DELETE ... WHERE
            # id IN (subquery), so this is a single statement.
            c.execute(
                'DELETE FROM audit_log WHERE id IN ('
                '  SELECT id FROM audit_log ORDER BY id DESC LIMIT -1 OFFSET ?'
                ')',
                (self.AUDIT_MAX_ROWS,)
            )

    def get_audit_log(self, limit=100, offset=0, action_prefix=None):
        sql = 'SELECT * FROM audit_log'
        args = []
        if action_prefix:
            sql += ' WHERE action LIKE ?'
            args.append(action_prefix + '%')
        sql += ' ORDER BY id DESC LIMIT ? OFFSET ?'
        args.extend([int(limit), int(offset)])
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, args)]

    def count_audit_log(self, action_prefix=None):
        sql = 'SELECT COUNT(*) FROM audit_log'
        args = []
        if action_prefix:
            sql += ' WHERE action LIKE ?'
            args.append(action_prefix + '%')
        with self._conn() as c:
            return c.execute(sql, args).fetchone()[0]
