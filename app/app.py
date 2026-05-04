import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import timedelta

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from config_generator import ConfigGenerator
from database import Database

# ═══════════════════════════════════════════════════════════════ Constants ══

_CONFIG_DIR          = os.environ.get('CONFIG_DIR', '/data/config')
_SERVICES_FILE       = os.path.join(_CONFIG_DIR, 'services.json')
_ADMIN_PASSWORD_FILE = os.path.join(_CONFIG_DIR, 'admin_password')
_SECRET_FILE         = os.path.join(_CONFIG_DIR, 'flask_secret')
_NAS_SSH_PORT        = os.environ.get('NAS_SSH_PORT', '2222')
_SHARES_ROOT         = os.path.realpath(os.environ.get('SHARES_DIR', '/data/shares'))

# ═══════════════════════════════════════════════════════════════ App init ═══

app = Flask(__name__)

# Trust X-Forwarded-* from a single reverse proxy (no-op if direct-exposed)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _load_or_create_secret():
    """Persistent Flask secret key. Survives restarts and is shared between
    gunicorn workers. Falls back to env var if explicitly set."""
    env = (os.environ.get('WEBUI_SECRET') or '').strip()
    if env:
        return env.encode()
    try:
        with open(_SECRET_FILE, 'rb') as f:
            data = f.read().strip()
            if len(data) >= 32:
                return data
    except FileNotFoundError:
        pass
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    new_key = secrets.token_hex(32).encode()
    fd = os.open(_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(new_key)
    return new_key


app.secret_key = _load_or_create_secret()

# True iff the UI is served over HTTPS (either by us or via reverse proxy).
# Set WEBUI_HTTPS=1 to enable Secure cookies.
_HTTPS = (os.environ.get('WEBUI_HTTPS', '') or '').lower() in ('1', 'true', 'yes')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=_HTTPS,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    WTF_CSRF_TIME_LIMIT=None,            # tokens valid for whole session
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # cap uploads (SSL files) at 2 MiB
)

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://',
)

db  = Database()
cfg = ConfigGenerator(db)

try:
    cfg.apply_all()
except Exception:
    pass

app.jinja_env.filters['from_json'] = lambda v: (
    json.loads(v) if isinstance(v, str) and v else (v if isinstance(v, list) else [])
)


# ═══════════════════════════════════════════════════════════════ Helpers ════

_NAME_RE      = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')
_USER_RE      = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')
_PATH_RE      = re.compile(r'^[A-Za-z0-9_./\-]{1,255}$')
_NFS_HOSTS_RE = re.compile(r'^[A-Za-z0-9_.\-/:*,\s]{1,255}$')
_NFS_OPT_RE   = re.compile(r'^[A-Za-z0-9_,=.\-]{1,255}$')
_CTRL_RE      = re.compile(r'[\x00-\x1f\x7f]')


def _strip_ctrl(s, maxlen=255):
    """Remove all control chars (incl. \\r \\n \\t) - prevents config injection
    when the value is written to smb.conf, /etc/exports, apache-shares.conf etc."""
    return _CTRL_RE.sub('', (s or ''))[:maxlen]


def _safe_share_path(p):
    """Confine share path to /data/shares/. Returns canonical path or None."""
    if not p or not _PATH_RE.match(p):
        return None
    rp = os.path.realpath(p)
    if rp == _SHARES_ROOT or rp.startswith(_SHARES_ROOT + os.sep):
        return rp
    return None


def _read_admin_hash():
    try:
        with open(_ADMIN_PASSWORD_FILE) as f:
            data = f.read().strip()
    except FileNotFoundError:
        return None
    if not data:
        return None
    # Werkzeug hash markers; otherwise treat as legacy plaintext and migrate.
    if data.startswith(('pbkdf2:', 'scrypt:', 'argon2')):
        return data
    migrated = generate_password_hash(data)
    _write_admin_hash(migrated)
    return migrated


def _write_admin_hash(hashed):
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    fd = os.open(_ADMIN_PASSWORD_FILE,
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(hashed)


def _verify_admin_password(pw):
    stored = _read_admin_hash()
    if stored:
        return check_password_hash(stored, pw)
    expected = os.environ.get('LOGIN_PASSWORD', 'admin')
    return secrets.compare_digest(pw, expected)


def _is_admin_default():
    """True if admin login still uses the built-in 'admin' fallback - shown
    as a banner in the UI."""
    if _read_admin_hash():
        return False
    return os.environ.get('LOGIN_PASSWORD', 'admin') == 'admin'


def _audit(action, target='', details='', actor=None):
    """Append an audit-log row. Never raise - logging must not break a request."""
    try:
        if actor is None:
            actor = 'admin' if session.get('logged_in') else 'anonymous'
        addr = ''
        try:
            addr = (request.remote_addr or '')
        except Exception:
            pass
        db.log_audit(actor, action, target, details, addr)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════ CSRF / headers

@app.errorhandler(CSRFError)
def _csrf_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'status': 'error', 'message': 'CSRF token missing or invalid'}), 400
    flash('Security token expired or missing - please retry.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))


@app.context_processor
def _inject_csrf():
    return {'csrf_token': generate_csrf}


@app.after_request
def _security_headers(resp):
    # CSP allows inline scripts/styles because the existing templates rely on
    # them. Tightening this requires a separate refactor.
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if _HTTPS:
        resp.headers.setdefault(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains'
        )
    return resp


# ═══════════════════════════════════════════════════════════════ Auth ════════

@app.before_request
def _check_auth():
    public = ('/login', '/logout', '/healthz')
    if request.path.startswith('/static/') or request.path in public:
        return
    if not session.get('logged_in'):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
        return redirect(url_for('login'))


@app.route('/healthz')
@csrf.exempt
def healthz():
    """Liveness probe for Docker / orchestrators. No auth, no CSRF."""
    try:
        db.get_stats()
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        if _verify_admin_password(request.form.get('password', '')):
            # Defeat session-fixation: drop any pre-login session id.
            session.clear()
            session['logged_in']  = True
            session.permanent     = True
            _audit('login.success', actor='admin')
            return redirect(url_for('dashboard'))
        _audit('login.fail', actor='anonymous')
        error = 'Incorrect password. Try again.'
    return render_template('login.html',
                           error=error,
                           is_default_password=_is_admin_default())


@app.route('/logout')
def logout():
    if session.get('logged_in'):
        _audit('logout', actor='admin')
    session.clear()
    return redirect(url_for('login'))


SERVICE_PROGRAMS = {
    'smb':    ['samba-smbd', 'samba-nmbd'],
    'nfs':    ['nfs'],
    'ftp':    ['vsftpd'],
    'sftp':   ['sshd'],
    'webdav': ['apache2'],
}


_DEFAULT_SERVICE_STATES = {
    'smb':    True,
    'nfs':    True,
    'ftp':    False,
    'sftp':   True,
    'webdav': True,
}

def _get_service_states():
    try:
        with open(_SERVICES_FILE) as f:
            states = json.load(f)
    except Exception:
        states = {}
    for k, default in _DEFAULT_SERVICE_STATES.items():
        states.setdefault(k, default)
    return states


def _save_service_states(states):
    os.makedirs(os.path.dirname(_SERVICES_FILE), exist_ok=True)
    with open(_SERVICES_FILE, 'w') as f:
        json.dump(states, f)


# ═══════════════════════════════════════════════════════════════ Dashboard ══

@app.route('/')
def dashboard():
    service_states = _get_service_states()
    services = cfg.get_service_statuses()
    for svc in services:
        svc['enabled'] = service_states.get(svc['protocol'], True)
    return render_template('dashboard.html',
                           services=services,
                           stats=db.get_stats(),
                           disk=_disk_usage(),
                           nas_host=_get_nas_host(),
                           nas_ssh_port=_NAS_SSH_PORT,
                           nas_host_configured=bool(os.environ.get('NAS_HOST', '').strip()),
                           is_default_password=_is_admin_default())


# ═══════════════════════════════════════════════════════════════ Shares ══════

@app.route('/shares')
def shares():
    return render_template('shares.html',
                           shares=db.get_all_shares(),
                           nas_host=_get_nas_host(),
                           nas_ssh_port=_NAS_SSH_PORT)


@app.route('/shares/new', methods=['GET', 'POST'])
def share_new():
    users = db.get_all_users()
    if request.method == 'POST':
        data, err = _parse_share_form(request.form)
        if err:
            flash(err, 'danger')
        else:
            try:
                db.create_share(data)
                os.makedirs(data['path'], exist_ok=True)
                _fix_share_dir(data['path'])
                cfg.apply_all(nas_host=_get_nas_host())
                _audit('share.create', target=data['name'],
                       details={'protocols': json.loads(data['protocols']),
                                'public': bool(data['public'])})
                flash(f"Share «{data['name']}» created.", 'success')
                return redirect(url_for('shares'))
            except Exception as e:
                flash(str(e), 'danger')
    return render_template('share_form.html', share=None, users=users,
                           nas_host_configured=bool(os.environ.get('NAS_HOST', '').strip()),
                           ssl_cert_expiry=_get_ssl_cert_expiry())


@app.route('/shares/<int:sid>/edit', methods=['GET', 'POST'])
def share_edit(sid):
    share = db.get_share(sid)
    users = db.get_all_users()
    if not share:
        flash('Share not found.', 'danger')
        return redirect(url_for('shares'))
    if request.method == 'POST':
        data, err = _parse_share_form(request.form)
        if err:
            flash(err, 'danger')
        else:
            try:
                db.update_share(sid, data)
                os.makedirs(data['path'], exist_ok=True)
                _fix_share_dir(data['path'])
                cfg.apply_all(nas_host=_get_nas_host())
                _audit('share.update', target=data['name'],
                       details={'protocols': json.loads(data['protocols']),
                                'public': bool(data['public'])})
                flash(f"Share «{data['name']}» updated.", 'success')
                return redirect(url_for('shares'))
            except Exception as e:
                flash(str(e), 'danger')
    return render_template('share_form.html', share=share, users=users,
                           nas_host_configured=bool(os.environ.get('NAS_HOST', '').strip()),
                           ssl_cert_expiry=_get_ssl_cert_expiry())


@app.route('/shares/<int:sid>/delete', methods=['POST'])
def share_delete(sid):
    share = db.get_share(sid)
    if share:
        try:
            db.delete_share(sid)
            cfg.apply_all(nas_host=_get_nas_host())
            _audit('share.delete', target=share['name'])
            flash(f"Share «{share['name']}» deleted.", 'success')
        except Exception as e:
            flash(str(e), 'danger')
    return redirect(url_for('shares'))


# ═══════════════════════════════════════════════════════════════ Users ═══════

@app.route('/users')
def users():
    return render_template('users.html', users=db.get_all_users())


@app.route('/users/new', methods=['GET', 'POST'])
def user_new():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        err = _validate_username(username)
        if err:
            flash(err, 'danger')
            return render_template('user_form.html', user=None)
        if not password or len(password) < 4:
            flash('Password is required (min 4 chars).', 'danger')
            return render_template('user_form.html', user=None)

        readonly = request.form.get('readonly') == 'on'
        try:
            db.create_user(username, readonly=readonly)
            _create_system_user(username, password)
            cfg.apply_all(nas_host=_get_nas_host())
            _audit('user.create', target=username, details={'readonly': readonly})
            flash(f"User «{username}» created.", 'success')
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), 'danger')
    return render_template('user_form.html', user=None)


@app.route('/users/<int:uid>/edit', methods=['GET', 'POST'])
def user_edit(uid):
    user = db.get_user(uid)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('users'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        enabled  = request.form.get('enabled') == 'on'
        readonly = request.form.get('readonly') == 'on'
        try:
            db.update_user(uid, enabled, readonly=readonly)
            pw_changed = False
            if password:
                if len(password) < 4:
                    flash('Password must be at least 4 characters.', 'danger')
                    return render_template('user_form.html', user=user)
                _set_password(user['username'], password)
                pw_changed = True
            _toggle_samba_user(user['username'], enabled)
            _toggle_system_user(user['username'], enabled)
            cfg.apply_all(nas_host=_get_nas_host())
            _audit('user.update', target=user['username'],
                   details={'enabled': enabled, 'readonly': readonly,
                            'password_changed': pw_changed})
            flash(f"User «{user['username']}» updated.", 'success')
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), 'danger')
    return render_template('user_form.html', user=user)


@app.route('/users/<int:uid>/delete', methods=['POST'])
def user_delete(uid):
    user = db.get_user(uid)
    if user:
        try:
            db.delete_user(uid)
            uname = user['username']
            if _USER_RE.match(uname):
                subprocess.run(['userdel', '-r', uname], check=False, capture_output=True)
                subprocess.run(['smbpasswd', '-x', uname], check=False, capture_output=True)
                _htpasswd_delete(uname)
            _audit('user.delete', target=uname)
            flash(f"User «{uname}» deleted.", 'success')
        except Exception as e:
            flash(str(e), 'danger')
    return redirect(url_for('users'))


# ══════════════════════════════════════════════════════════════ Audit log ════

# Allow-list of action prefixes a user can filter by - keeps the LIKE
# parameter from accepting arbitrary input.
_AUDIT_FILTERS = ('user', 'share', 'service', 'admin', 'login', 'logout', 'ssl')


@app.route('/audit')
def audit_log():
    page   = max(int(request.args.get('page',  1)  or 1), 1)
    filt   = request.args.get('filter', '') or ''
    if filt and filt not in _AUDIT_FILTERS:
        filt = ''
    per_page = 100
    offset   = (page - 1) * per_page
    rows  = db.get_audit_log(limit=per_page, offset=offset,
                             action_prefix=filt or None)
    total = db.count_audit_log(action_prefix=filt or None)
    pages = max((total + per_page - 1) // per_page, 1)
    return render_template('audit.html',
                           rows=rows, page=page, pages=pages,
                           total=total, filt=filt,
                           filters=_AUDIT_FILTERS)


@app.route('/api/audit')
def api_audit():
    limit  = min(max(int(request.args.get('limit', 100) or 100), 1), 500)
    offset = max(int(request.args.get('offset', 0) or 0), 0)
    filt   = request.args.get('filter', '') or ''
    if filt and filt not in _AUDIT_FILTERS:
        filt = ''
    return jsonify(db.get_audit_log(limit=limit, offset=offset,
                                    action_prefix=filt or None))


# ══════════════════════════════════════════════════════════════ Settings ═════

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pw  = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not _verify_admin_password(current):
            flash('Current password is incorrect.', 'danger')
        elif len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'danger')
        elif new_pw != confirm:
            flash('New passwords do not match.', 'danger')
        else:
            try:
                _write_admin_hash(generate_password_hash(new_pw))
                _audit('admin.password_change')
                flash('Password changed successfully.', 'success')
            except Exception as e:
                flash(f'Failed to save password: {e}', 'danger')
    return render_template('settings.html',
                           is_default_password=_is_admin_default())


@app.route('/settings/ssl', methods=['POST'])
def settings_ssl():
    cert_file = request.files.get('ssl_cert')
    key_file  = request.files.get('ssl_key')
    ssl_dir   = os.path.join(_CONFIG_DIR, 'ssl')
    os.makedirs(ssl_dir, exist_ok=True)

    if not (cert_file and cert_file.filename) and not (key_file and key_file.filename):
        flash('No files were uploaded.', 'warning')
        return redirect(request.referrer or url_for('shares'))

    err = _replace_ssl_pair(ssl_dir, cert_file, key_file)
    if err:
        _audit('ssl.upload', target='rejected', details={'reason': err})
        flash(f'Certificate update rejected: {err}', 'danger')
    else:
        subprocess.run(['apache2ctl', 'graceful'], check=False, capture_output=True)
        _audit('ssl.upload', target='installed')
        flash('SSL certificate updated. Apache reloaded.', 'success')
    return redirect(request.referrer or url_for('shares'))


def _replace_ssl_pair(ssl_dir, cert_file, key_file):
    """Validate uploaded cert and key with openssl, ensure they pair, then
    install atomically. Returns error string or None."""
    final_cert = os.path.join(ssl_dir, 'server.crt')
    final_key  = os.path.join(ssl_dir, 'server.key')

    with tempfile.TemporaryDirectory() as tmp:
        tmp_cert = os.path.join(tmp, 'cert.pem')
        tmp_key  = os.path.join(tmp, 'key.pem')

        if cert_file and cert_file.filename:
            cert_file.save(tmp_cert)
        elif os.path.exists(final_cert):
            shutil.copy(final_cert, tmp_cert)
        else:
            return 'certificate file is required for first install'

        if key_file and key_file.filename:
            key_file.save(tmp_key)
        elif os.path.exists(final_key):
            shutil.copy(final_key, tmp_key)
        else:
            return 'private key file is required for first install'

        for path, max_size in ((tmp_cert, 64 * 1024), (tmp_key, 64 * 1024)):
            if os.path.getsize(path) > max_size:
                return 'file too large'

        cert_chk = subprocess.run(
            ['openssl', 'x509', '-in', tmp_cert, '-noout', '-modulus'],
            capture_output=True, text=True
        )
        if cert_chk.returncode != 0:
            return 'invalid X.509 certificate'

        key_chk = subprocess.run(
            ['openssl', 'pkey', '-in', tmp_key, '-noout', '-pubout', '-outform', 'PEM'],
            capture_output=True, text=True
        )
        if key_chk.returncode != 0:
            # try RSA-only as a fallback for older formats
            key_chk = subprocess.run(
                ['openssl', 'rsa', '-in', tmp_key, '-noout', '-modulus'],
                capture_output=True, text=True
            )
            if key_chk.returncode != 0:
                return 'invalid private key'

        # cert/key must match: compare modulus
        cert_mod = subprocess.run(
            ['openssl', 'x509', '-in', tmp_cert, '-noout', '-modulus'],
            capture_output=True, text=True
        ).stdout.strip()
        key_mod = subprocess.run(
            ['openssl', 'rsa', '-in', tmp_key, '-noout', '-modulus'],
            capture_output=True, text=True
        ).stdout.strip()
        # ECDSA keys won't have a modulus; accept those without comparison.
        if cert_mod and key_mod and cert_mod != key_mod:
            return 'certificate and private key do not match'

        # Install atomically
        os.replace(tmp_cert, final_cert)
        os.replace(tmp_key,  final_key)
        os.chmod(final_cert, 0o644)
        os.chmod(final_key,  0o600)
    return None


# ═══════════════════════════════════════════════════════════════ API ═════════

@app.route('/api/services/reload', methods=['POST'])
def api_reload():
    try:
        cfg.apply_all(nas_host=_get_nas_host())
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/services/status')
def api_status():
    states = _get_service_states()
    statuses = cfg.get_service_statuses()
    for svc in statuses:
        svc['enabled'] = states.get(svc['protocol'], True)
    return jsonify(statuses)


@app.route('/api/shares')
def api_shares():
    return jsonify(db.get_all_shares())


@app.route('/api/users')
def api_users():
    return jsonify(db.get_all_users())


@app.route('/api/services/<svc>/toggle', methods=['POST'])
def api_toggle_service(svc):
    if svc not in SERVICE_PROGRAMS:
        return jsonify({'status': 'error', 'message': 'Unknown service'}), 400

    states = _get_service_states()
    states[svc] = not states.get(svc, True)
    _save_service_states(states)

    supervisorctl_cmd = 'start' if states[svc] else 'stop'
    for prog in SERVICE_PROGRAMS[svc]:
        subprocess.run(['supervisorctl', supervisorctl_cmd, prog],
                       capture_output=True)

    _audit('service.toggle', target=svc, details={'enabled': states[svc]})
    return jsonify({'status': 'ok', 'enabled': states[svc]})


# ═══════════════════════════════════════════════════════════════ Helpers ═════

def _validate_username(u):
    if not u:
        return 'Username is required.'
    if not _USER_RE.match(u):
        return 'Username must start with a letter, contain only lowercase letters/digits/_/-, max 32 chars.'
    return None


def _parse_share_form(form):
    name = _strip_ctrl(form.get('name', '').strip(), 64)
    if not name or not _NAME_RE.match(name):
        return None, 'Invalid share name (letters, digits, - _ only).'

    raw_path = _strip_ctrl(form.get('path', '').strip(), 255) or f'/data/shares/{name}'
    safe_path = _safe_share_path(raw_path)
    if not safe_path:
        return None, f'Path must stay within {_SHARES_ROOT} (allowed chars: A-Z a-z 0-9 _ . - /).'

    comment   = _strip_ctrl(form.get('comment', '').strip(), 255)
    protocols = [p for p in form.getlist('protocols')
                 if p in ('smb', 'nfs', 'ftp', 'sftp', 'webdav')]
    public    = 1 if form.get('public') == 'on' else 0

    nfs_hosts_raw = _strip_ctrl(form.get('nfs_hosts', '*').strip(), 255) or '*'
    if not _NFS_HOSTS_RE.match(nfs_hosts_raw):
        return None, 'NFS hosts contains invalid characters.'

    nfs_opts_raw = _strip_ctrl(
        form.get('nfs_options', 'rw,sync,no_subtree_check,root_squash').strip(), 255)
    if not _NFS_OPT_RE.match(nfs_opts_raw):
        return None, 'NFS options contains invalid characters (allowed: a-z 0-9 _ , = . -).'

    usernames = form.getlist('access_user[]')
    levels    = form.getlist('access_level[]')
    access_list = []
    for u, a in zip(usernames, levels):
        u = (u or '').strip().lower()
        if not u or not _USER_RE.match(u):
            continue
        access_list.append({'username': u, 'access': 'rw' if a != 'ro' else 'ro'})

    timemachine           = 1 if (form.get('timemachine')           == 'on' and 'smb' in protocols) else 0
    smb_guest_write       = 1 if (form.get('smb_guest_write')       == 'on' and 'smb' in protocols and public) else 0
    smb_async_io          = 1 if form.get('smb_async_io')           == 'on' else 0
    smb_sync_writes       = 1 if form.get('smb_sync_writes')        == 'on' else 0
    webdav_inline_preview = 1 if (form.get('webdav_inline_preview') == 'on' and 'webdav' in protocols) else 0

    return {
        'name':                  name,
        'path':                  safe_path,
        'comment':               comment,
        'protocols':             json.dumps(protocols),
        'public':                public,
        'smb_guest_write':       smb_guest_write,
        'nfs_hosts':             nfs_hosts_raw,
        'nfs_options':           nfs_opts_raw,
        'access_list':           json.dumps(access_list),
        'timemachine':           timemachine,
        'smb_async_io':          smb_async_io,
        'smb_sync_writes':       smb_sync_writes,
        'webdav_inline_preview': webdav_inline_preview,
    }, None


def _fix_share_dir(path):
    safe = _safe_share_path(path)
    if not safe:
        return
    try:
        os.chmod(safe, 0o775)
        subprocess.run(['chown', 'root:nasusers', safe], check=False, capture_output=True)
    except Exception:
        pass


def _create_system_user(username, password):
    if not _USER_RE.match(username):
        raise ValueError('invalid username')
    subprocess.run(
        ['useradd', '-s', '/usr/sbin/nologin', '-d', '/data/shares',
         '-G', 'nasusers', username],
        check=True, capture_output=True
    )
    _set_password(username, password)


def _set_password(username, password):
    if not _USER_RE.match(username):
        raise ValueError('invalid username')

    # System password: hash via openssl, then usermod -p (avoids PAM issues in Docker)
    result = subprocess.run(
        ['openssl', 'passwd', '-6', '-stdin'],
        input=password, capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        subprocess.run(['usermod', '-p', result.stdout.strip(), username],
                       check=False, capture_output=True)
    else:
        p = subprocess.Popen(['chpasswd'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.communicate(input=f'{username}:{password}\n'.encode())

    # Samba password (force fresh entry)
    subprocess.run(['smbpasswd', '-x', username], capture_output=True)
    p = subprocess.Popen(
        ['smbpasswd', '-a', '-s', username],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    p.communicate(input=f'{password}\n{password}\n'.encode())
    subprocess.run(['smbpasswd', '-e', username], capture_output=True)

    _htpasswd_set(username, password)


def _htpasswd_set(username, password):
    """Update WebDAV htpasswd file. Uses -i (stdin) so the password never
    appears in the process list."""
    htpasswd = os.path.join(_CONFIG_DIR, 'webdav.passwords')
    if not os.path.exists(htpasswd):
        # Create empty file with restrictive perms before htpasswd touches it.
        fd = os.open(htpasswd, os.O_WRONLY | os.O_CREAT, 0o640)
        os.close(fd)
    p = subprocess.Popen(
        ['htpasswd', '-i', htpasswd, username],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    p.communicate(input=password.encode())
    # Apache (www-data) must read this file; htpasswd preserves owner but we
    # re-assert group + mode in case of fresh creation or perms drift.
    try:
        shutil.chown(htpasswd, group='www-data')
        os.chmod(htpasswd, 0o640)
    except Exception:
        pass


def _toggle_samba_user(username, enabled):
    if not _USER_RE.match(username):
        return
    flag = '-e' if enabled else '-d'
    subprocess.run(['smbpasswd', flag, username], check=False, capture_output=True)


def _toggle_system_user(username, enabled):
    if not _USER_RE.match(username):
        return
    flag = '-U' if enabled else '-L'
    subprocess.run(['usermod', flag, username], check=False, capture_output=True)


def _htpasswd_delete(username):
    if not _USER_RE.match(username):
        return
    htpasswd = os.path.join(_CONFIG_DIR, 'webdav.passwords')
    subprocess.run(['htpasswd', '-D', htpasswd, username],
                   check=False, capture_output=True)


# Allow-list of host headers we'll accept as 'self'. If unset, we reject
# anything beyond the configured NAS_HOST or local addresses.
_HOST_ALLOWLIST_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,253}(:\d{1,5})?$')


def _get_nas_host():
    explicit = (os.environ.get('NAS_HOST') or '').strip()
    if explicit:
        return explicit
    try:
        host = (request.host or '').split(':')[0]
        if host and _HOST_ALLOWLIST_RE.match(host):
            return host
    except Exception:
        pass
    return ''


def _get_ssl_cert_expiry():
    cert_path = os.path.join(_CONFIG_DIR, 'ssl', 'server.crt')
    try:
        r = subprocess.run(
            ['openssl', 'x509', '-enddate', '-noout', '-in', cert_path],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            return r.stdout.strip().replace('notAfter=', '')
    except Exception:
        pass
    return None


def _fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024.0:
            return f'{n:.1f} {unit}'
        n /= 1024.0
    return f'{n:.1f} PB'


def _disk_usage():
    try:
        u = shutil.disk_usage('/data/shares')
        pct = round(u.used / u.total * 100, 1) if u.total else 0
        return {
            'total_h':   _fmt_bytes(u.total),
            'used_h':    _fmt_bytes(u.used),
            'free_h':    _fmt_bytes(u.free),
            'percent':   pct,
        }
    except Exception:
        return None


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
