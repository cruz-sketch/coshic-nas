import json
import os
import re
import shutil
import subprocess

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

from config_generator import ConfigGenerator
from database import Database

app = Flask(__name__)
app.secret_key = os.environ.get('WEBUI_SECRET', 'nas-dev-secret-change-me')

db  = Database()
cfg = ConfigGenerator(db)

# Regenerate all service configs on startup (writes portal page, smb.conf, etc.)
try:
    cfg.apply_all()
except Exception:
    pass

app.jinja_env.filters['from_json'] = lambda v: (
    json.loads(v) if isinstance(v, str) and v else (v if isinstance(v, list) else [])
)

_CONFIG_DIR           = os.environ.get('CONFIG_DIR', '/data/config')
_SERVICES_FILE        = os.path.join(_CONFIG_DIR, 'services.json')
_ADMIN_PASSWORD_FILE  = os.path.join(_CONFIG_DIR, 'admin_password')
_NAS_SSH_PORT         = os.environ.get('NAS_SSH_PORT', '2222')


def _get_admin_password():
    """Read password from persistent file; fall back to env var (default: admin)."""
    try:
        with open(_ADMIN_PASSWORD_FILE) as f:
            pw = f.read().strip()
            if pw:
                return pw
    except Exception:
        pass
    return os.environ.get('LOGIN_PASSWORD', 'admin')


# ═══════════════════════════════════════════════════════════════ Auth ════════

@app.before_request
def _check_auth():
    """Redirect to login for all protected routes."""
    public = ('/login', '/logout')
    if request.path.startswith('/static/') or request.path in public:
        return
    if not session.get('logged_in'):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        if request.form.get('password') == _get_admin_password():
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        error = 'Incorrect password. Try again.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
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
                           nas_host_configured=bool(os.environ.get('NAS_HOST', '').strip()))


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
        if not password:
            flash('Password is required.', 'danger')
            return render_template('user_form.html', user=None)

        readonly = request.form.get('readonly') == 'on'
        try:
            db.create_user(username, readonly=readonly)
            _create_system_user(username, password)
            cfg.apply_all(nas_host=_get_nas_host())
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
            if password:
                _set_password(user['username'], password)
            _toggle_samba_user(user['username'], enabled)
            _toggle_system_user(user['username'], enabled)
            cfg.apply_all(nas_host=_get_nas_host())
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
            subprocess.run(['userdel', '-r', user['username']], check=False, capture_output=True)
            subprocess.run(['smbpasswd', '-x', user['username']], check=False, capture_output=True)
            # remove from webdav passwords
            _htpasswd_delete(user['username'])
            flash(f"User «{user['username']}» deleted.", 'success')
        except Exception as e:
            flash(str(e), 'danger')
    return redirect(url_for('users'))


# ══════════════════════════════════════════════════════════════ Settings ═════

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pw  = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if current != _get_admin_password():
            flash('Current password is incorrect.', 'danger')
        elif len(new_pw) < 4:
            flash('New password must be at least 4 characters.', 'danger')
        elif new_pw != confirm:
            flash('New passwords do not match.', 'danger')
        else:
            try:
                os.makedirs(os.path.dirname(_ADMIN_PASSWORD_FILE), exist_ok=True)
                with open(_ADMIN_PASSWORD_FILE, 'w') as f:
                    f.write(new_pw)
                flash('Password changed successfully.', 'success')
            except Exception as e:
                flash(f'Failed to save password: {e}', 'danger')
    return render_template('settings.html')


@app.route('/settings/ssl', methods=['POST'])
def settings_ssl():
    cert_file = request.files.get('ssl_cert')
    key_file  = request.files.get('ssl_key')
    ssl_dir   = os.path.join(_CONFIG_DIR, 'ssl')
    os.makedirs(ssl_dir, exist_ok=True)
    saved = False
    if cert_file and cert_file.filename:
        cert_file.save(os.path.join(ssl_dir, 'server.crt'))
        saved = True
    if key_file and key_file.filename:
        key_file.save(os.path.join(ssl_dir, 'server.key'))
        saved = True
    if saved:
        subprocess.run(['apache2ctl', 'graceful'], check=False, capture_output=True)
        flash('SSL certificate updated. Apache reloaded.', 'success')
    else:
        flash('No files were uploaded.', 'warning')
    return redirect(request.referrer or url_for('shares'))


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

    return jsonify({'status': 'ok', 'enabled': states[svc]})


# ═══════════════════════════════════════════════════════════════ Helpers ═════

_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')
_USER_RE = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')


def _validate_username(u):
    if not u:
        return 'Username is required.'
    if not _USER_RE.match(u):
        return 'Username must start with a letter, contain only lowercase letters/digits/_/-, max 32 chars.'
    return None


def _parse_share_form(form):
    name = form.get('name', '').strip()
    if not name or not _NAME_RE.match(name):
        return None, 'Invalid share name (letters, digits, - _ only).'

    path = form.get('path', '').strip() or f'/data/shares/{name}'
    comment   = form.get('comment', '').strip()
    protocols = form.getlist('protocols')
    public    = 1 if form.get('public') == 'on' else 0
    nfs_hosts = form.get('nfs_hosts', '*').strip() or '*'
    nfs_opts  = form.get('nfs_options', 'rw,sync,no_subtree_check,no_root_squash').strip()

    usernames = form.getlist('access_user[]')
    levels    = form.getlist('access_level[]')
    access_list = [{'username': u, 'access': a}
                   for u, a in zip(usernames, levels) if u]

    timemachine           = 1 if (form.get('timemachine')           == 'on' and 'smb' in protocols) else 0
    smb_guest_write       = 1 if (form.get('smb_guest_write')       == 'on' and 'smb' in protocols and public) else 0
    smb_async_io          = 1 if form.get('smb_async_io')           == 'on' else 0
    smb_sync_writes       = 1 if form.get('smb_sync_writes')        == 'on' else 0
    webdav_inline_preview = 1 if (form.get('webdav_inline_preview') == 'on' and 'webdav' in protocols) else 0

    return {
        'name':                 name,
        'path':                 path,
        'comment':              comment,
        'protocols':            json.dumps(protocols),
        'public':               public,
        'smb_guest_write':      smb_guest_write,
        'nfs_hosts':            nfs_hosts,
        'nfs_options':          nfs_opts,
        'access_list':          json.dumps(access_list),
        'timemachine':          timemachine,
        'smb_async_io':         smb_async_io,
        'smb_sync_writes':      smb_sync_writes,
        'webdav_inline_preview': webdav_inline_preview,
    }, None


def _fix_share_dir(path):
    """Set share directory to nasusers group with group-write."""
    try:
        os.chmod(path, 0o775)
        subprocess.run(['chown', 'root:nasusers', path], check=False, capture_output=True)
    except Exception:
        pass


def _create_system_user(username, password):
    subprocess.run(
        ['useradd', '-s', '/usr/sbin/nologin', '-d', '/data/shares', '-G', 'nasusers', username],
        check=True, capture_output=True
    )
    _set_password(username, password)


def _set_password(username, password):
    # Generate SHA-512 hash directly via openssl to avoid PAM/chpasswd interactions in Docker.
    result = subprocess.run(
        ['openssl', 'passwd', '-6', '-stdin'],
        input=password, capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        subprocess.run(['usermod', '-p', result.stdout.strip(), username],
                       check=False, capture_output=True)
    else:
        p = subprocess.Popen(['chpasswd'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate(input=f'{username}:{password}\n'.encode())

    # Remove stale Samba DB entry if it exists, then add fresh.
    # smbpasswd -a fails silently when user already exists, leaving the password unchanged.
    subprocess.run(['smbpasswd', '-x', username], capture_output=True)
    p = subprocess.Popen(
        ['smbpasswd', '-a', '-s', username],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    p.communicate(input=f'{password}\n{password}\n'.encode())
    subprocess.run(['smbpasswd', '-e', username], capture_output=True)

    config_dir = os.environ.get('CONFIG_DIR', '/data/config')
    htpasswd = f'{config_dir}/webdav.passwords'
    flag = '-b' if os.path.exists(htpasswd) and username in open(htpasswd).read() else '-cb'
    subprocess.run(['htpasswd', flag, htpasswd, username, password],
                   check=False, capture_output=True)


def _toggle_samba_user(username, enabled):
    flag = '-e' if enabled else '-d'
    subprocess.run(['smbpasswd', flag, username], check=False, capture_output=True)


def _toggle_system_user(username, enabled):
    """Lock or unlock the Linux account to block/allow FTP and SFTP access."""
    flag = '-U' if enabled else '-L'
    subprocess.run(['usermod', flag, username], check=False, capture_output=True)


def _htpasswd_delete(username):
    config_dir = os.environ.get('CONFIG_DIR', '/data/config')
    htpasswd = f'{config_dir}/webdav.passwords'
    subprocess.run(['htpasswd', '-D', htpasswd, username], check=False, capture_output=True)


def _get_nas_host():
    """Return the NAS host address to show in Connection Info.
    Priority: NAS_HOST env var → hostname from the browser request → empty string."""
    explicit = os.environ.get('NAS_HOST', '').strip()
    if explicit:
        return explicit
    try:
        # request.host is e.g. "192.168.1.10:8080" - strip the port
        return request.host.split(':')[0]
    except Exception:
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
