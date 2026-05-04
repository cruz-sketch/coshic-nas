import json
import os
import re
import subprocess

CONFIG_DIR  = os.environ.get('CONFIG_DIR',  '/data/config')
SHARES_DIR  = os.environ.get('SHARES_DIR',  '/data/shares')

# Defence-in-depth: even if app.py validation is bypassed somehow, scrub control
# chars before writing values to service config files (smb.conf / exports / apache).
_CTRL_RE = re.compile(r'[\x00-\x1f\x7f]')
_USER_RE = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')


def _safe(s, maxlen=255):
    return _CTRL_RE.sub('', (s or ''))[:maxlen]


def _safe_user(u):
    """Return username if it matches the strict pattern, else None.
    Used everywhere a username is interpolated into a config file."""
    u = (u or '').strip()
    return u if _USER_RE.match(u) else None


class ConfigGenerator:
    def __init__(self, db):
        self.db = db

    def apply_all(self, nas_host=''):
        shares = self.db.get_all_shares()
        users  = self.db.get_all_users()
        errors = []
        for fn in (
            lambda: self._apply_samba(shares, users),
            lambda: self._apply_nfs(shares),
            lambda: self._apply_webdav(shares),
            lambda: self._apply_ftp_config(shares, nas_host),
            lambda: self._apply_ftp_users(users),
            lambda: self._apply_sftp_users(users),
            lambda: self._apply_avahi_timemachine(shares),
            lambda: self._apply_portal(shares),
        ):
            try:
                fn()
            except Exception as e:
                errors.append(str(e))
        if errors:
            raise RuntimeError('; '.join(errors))

    # ------------------------------------------------------------------ Samba
    def _apply_samba(self, shares, users):
        readonly_users = {u['username'] for u in users if u.get('readonly', 0)}

        has_timemachine = any(
            s.get('timemachine', 0) for s in shares if 'smb' in self._protocols(s)
        )

        lines = [
            '[global]',
            '   workgroup = WORKGROUP',
            '   server string = Coshic NAS',
            '   security = user',
            '   map to guest = bad user',
            '   log file = /var/log/samba/log.%m',
            '   max log size = 1000',
            '   dns proxy = no',
            '   socket options = TCP_NODELAY IPTOS_LOWDELAY',
        ]

        if has_timemachine:
            lines += [
                '   vfs objects = catia fruit streams_xattr',
                '   fruit:metadata = stream',
                '   fruit:posix_rename = yes',
                '   fruit:veto_appledouble = no',
                '   fruit:wipe_intentionally_left_blank_rfork = yes',
                '   fruit:delete_empty_adfiles = yes',
            ]

        lines.append('')

        for s in shares:
            if 'smb' not in self._protocols(s):
                continue

            access = self._access(s)
            valid_users = [vu for vu in
                           (_safe_user(a.get('username')) for a in access)
                           if vu]
            # A user gets write access only if: share grants rw AND user is not globally readonly
            write_users = [vu for vu in
                           (_safe_user(a.get('username')) for a in access
                            if a.get('access') == 'rw')
                           if vu and vu not in readonly_users]
            is_public = bool(s.get('public', 0))

            name = _safe(s.get('name', ''), 64)
            path = _safe(s.get('path', ''), 255)

            # Default-deny: a private share without any allowed users would
            # otherwise grant access to ALL authenticated samba users (since
            # 'valid users' would be omitted). Skip the section entirely.
            if not is_public and not valid_users:
                continue

            lines += [f"[{name}]",
                      f"   path = {path}",
                      f"   comment = {_safe(s.get('comment', ''), 255)}",
                      '   browseable = yes',
                      '   create mask = 0664',
                      '   directory mask = 0775']

            if is_public:
                lines += ['   guest ok = yes', '   read only = no']
                if s.get('smb_guest_write', 0):
                    lines.append('   force group = nasusers')
            else:
                lines.append('   read only = no')
                lines.append(f"   valid users = {' '.join(valid_users)}")
                if write_users:
                    lines.append(f"   write list = {' '.join(write_users)}")

            if s.get('timemachine', 0):
                lines += [
                    '   fruit:time machine = yes',
                    '   fruit:time machine max size = 0',
                ]

            if s.get('smb_async_io', 1):
                lines += [
                    '   use sendfile = yes',
                    '   aio read size = 16384',
                    '   aio write size = 16384',
                    '   min receivefile size = 16384',
                ]

            if s.get('smb_sync_writes', 0):
                lines += ['   strict sync = yes', '   sync always = yes']
            else:
                lines += ['   strict sync = no',  '   sync always = no']

            lines.append('')

        self._write('/etc/samba/smb.conf', '\n'.join(lines))
        subprocess.run(['pkill', '-HUP', 'smbd'], check=False, capture_output=True)

    # -------------------------------------------------------------------- NFS
    _NFS_HOSTS_RE = re.compile(r'^[A-Za-z0-9_.\-/:*,\s]{1,255}$')
    _NFS_OPT_RE   = re.compile(r'^[A-Za-z0-9_,=.\-]{1,255}$')

    def _apply_nfs(self, shares):
        nfs_shares = [s for s in shares if 'nfs' in self._protocols(s)]
        lines = []

        if nfs_shares:
            # NFSv4 pseudo-root - without this the kernel NFS server refuses all NFSv4 connections
            lines.append(f'{SHARES_DIR} *(ro,fsid=root,no_subtree_check,root_squash)')

        for s in nfs_shares:
            path  = _safe(s.get('path', ''), 255)
            if not path:
                continue
            hosts = _safe((s.get('nfs_hosts') or '*').strip(), 255) or '*'
            opts  = _safe(
                (s.get('nfs_options') or 'rw,sync,no_subtree_check,root_squash').strip(),
                255)
            if not self._NFS_HOSTS_RE.match(hosts) or not self._NFS_OPT_RE.match(opts):
                # Skip malformed entries rather than corrupt /etc/exports
                continue
            lines.append(f"{path} {hosts}({opts})")

        self._write('/etc/exports', '\n'.join(lines) + ('\n' if lines else ''))
        subprocess.run(['exportfs', '-ra'], check=False, capture_output=True)

    # ----------------------------------------------------------------- WebDAV
    def _apply_webdav(self, shares):
        ui_dir = '/etc/apache2/webdav-ui'
        self._write_webdav_ui(ui_dir)

        lines = [
            f'Alias /webdav-ui/ {ui_dir}/',
            f'<Directory {ui_dir}/>',
            '    Require all granted',
            '    Options None',
            '    AllowOverride None',
            '</Directory>',
            '',
        ]

        for s in shares:
            if 'webdav' not in self._protocols(s):
                continue
            name = _safe(s.get('name', ''), 64)
            path = _safe(s.get('path', ''), 255)
            if not name or not path:
                continue
            is_public = s.get('public', 0)

            lines += [
                f'Alias /{name} {path}',
                f'<Directory {path}>',
                '    DAV On',
                # SymLinksIfOwnerMatch prevents users from following symlinks
                # that point outside the share (e.g. ln -s / leak)
                '    Options Indexes SymLinksIfOwnerMatch',
                '    AllowOverride None',
                '    IndexOptions FancyIndexing HTMLTable SuppressHTMLPreamble SuppressDescription VersionSort NameWidth=*',
                '    HeaderName /webdav-ui/header.html',
                '    ReadmeName /webdav-ui/footer.html',
            ]

            if not s.get('webdav_inline_preview', 0):
                lines += [
                    '    <FilesMatch ".+">',
                    '        Header always set Content-Disposition "attachment"',
                    '    </FilesMatch>',
                ]

            if not is_public:
                lines += [
                    '    AuthType Basic',
                    f'    AuthName "Coshic NAS - {name}"',
                    f'    AuthUserFile {CONFIG_DIR}/webdav.passwords',
                    '    Require valid-user',
                ]
            else:
                lines.append('    Require all granted')

            lines += ['</Directory>', '']

        conf_path = os.path.join(CONFIG_DIR, 'apache-shares.conf')
        self._write(conf_path, '\n'.join(lines))
        subprocess.run(['apache2ctl', 'graceful'], check=False, capture_output=True)

    def _write_webdav_ui(self, ui_dir):
        header = '''\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Files - Coshic NAS</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       background: #f4f5fb; color: #1e2030; min-height: 100vh; }
header { background: #13152a; color: #fff; padding: 0 32px;
         display: flex; align-items: center; justify-content: space-between;
         height: 64px; box-shadow: 0 2px 16px rgba(0,0,0,.35); }
.brand { display: flex; align-items: center; gap: 12px; font-size: 18px;
         font-weight: 700; text-decoration: none; color: #fff; }
.brand-icon { width: 36px; height: 36px; background: #4f6ef7; border-radius: 10px;
              display: flex; align-items: center; justify-content: center; }
.manage-btn { background: #4f6ef7; color: #fff; border: none; border-radius: 8px;
              padding: 8px 18px; font-size: 13px; font-weight: 600;
              text-decoration: none; transition: background .15s; white-space: nowrap; }
.manage-btn:hover { background: #3d5ae6; }
main { max-width: 900px; margin: 0 auto; padding: 28px 20px 60px; }
.crumb { display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
         margin-bottom: 16px; font-size: 13px; }
.crumb a { color: #4f6ef7; text-decoration: none; font-weight: 500; }
.crumb a:hover { text-decoration: underline; }
.crumb-sep { color: #c0c6d8; user-select: none; }
.crumb-cur { color: #8890a4; }
.listing-card { background: #fff; border: 1px solid #e8eaf0;
                border-radius: 14px; overflow: hidden; }
table { width: 100%; border-collapse: collapse; }
table tr.hdr th { padding: 11px 20px; background: #f8f9ff;
                  border-bottom: 1px solid #e8eaf0; font-size: 11px;
                  font-weight: 700; text-transform: uppercase; letter-spacing: .5px;
                  color: #8890a4; text-align: left; }
table tr.hdr th:last-child { text-align: right; }
table tr.hdr th a { color: inherit; text-decoration: none; }
table tr.hdr th a:hover { color: #4f6ef7; }
table tr.sep { display: none; }
table tr.row td { padding: 9px 20px; border-bottom: 1px solid #f0f2f8;
                  font-size: 13.5px; vertical-align: middle; }
table tr.row:last-of-type td { border-bottom: none; }
table tr.row:hover td { background: #fafbff; }
table td img { display: none; }
.file-name { display: flex; align-items: center; gap: 10px; }
.file-name a { color: #1e2030; text-decoration: none; font-weight: 500;
               overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-name a:hover { color: #4f6ef7; }
.f-icon { width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
          display: flex; align-items: center; justify-content: center; font-size: 15px; }
table td:nth-child(2) { color: #8890a4; font-size: 12px; white-space: nowrap; text-align: right; }
table td:nth-child(3) { color: #8890a4; font-size: 12px; white-space: nowrap;
                         text-align: right; width: 72px; }
address { display: none; }
</style>
</head>
<body>
<header>
  <a class="brand" href="/">
    <div class="brand-icon">
      <svg width="20" height="20" fill="white" viewBox="0 0 16 16">
        <path d="M2 2a2 2 0 0 0-2 2v1a2 2 0 0 0 2 2h5.5v3A1.5 1.5 0 0 0 6 11.5H.5a.5.5 0 0 0 0 1H6A1.5 1.5 0 0 0 7.5 14h1a1.5 1.5 0 0 0 1.5-1.5h5.5a.5.5 0 0 0 0-1H10A1.5 1.5 0 0 0 8.5 10V7H14a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zm.5 3a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m2 0a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1M14.5 5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1"/>
      </svg>
    </div>
    <span>Coshic NAS</span>
  </a>
  <a href="#" id="mgr" class="manage-btn">&#9881; Manage</a>
  <script>document.getElementById('mgr').href='http://'+location.hostname+':8080';</script>
</header>
<main>
  <nav class="crumb" id="crumb"></nav>
  <div class="listing-card">
'''

        footer = '''\
  </div>
</main>
<script>
(function () {
  // Breadcrumb from URL path
  var segs = location.pathname.replace(/\\/+$/, '').split('/').filter(Boolean);
  var html = '<a href="/">Home</a>', acc = '';
  for (var i = 0; i < segs.length; i++) {
    acc += '/' + segs[i];
    html += '<span class="crumb-sep">&#8250;</span>';
    html += i === segs.length - 1
      ? '<span class="crumb-cur">' + decodeURIComponent(segs[i]) + '</span>'
      : '<a href="' + acc + '/">' + decodeURIComponent(segs[i]) + '</a>';
  }
  document.getElementById('crumb').innerHTML = html;

  // Icon definitions
  var byAlt = {
    '[PARENTDIR]': {e:'&#x21A9;', bg:'#f0f2f8', c:'#8890a4'},
    '[DIR]':       {e:'&#x1F4C1;', bg:'#fff8e1', c:'#f59e0b'},
    '[IMG]':       {e:'&#x1F5BC;', bg:'#f0fff4', c:'#22c55e'},
    '[VID]':       {e:'&#x1F3AC;', bg:'#fdf2ff', c:'#a855f7'},
    '[SND]':       {e:'&#x1F3B5;', bg:'#fdf2ff', c:'#a855f7'},
  };
  var byExt = {
    jpg:'[IMG]',jpeg:'[IMG]',png:'[IMG]',gif:'[IMG]',svg:'[IMG]',webp:'[IMG]',bmp:'[IMG]',ico:'[IMG]',
    mp4:'[VID]',mkv:'[VID]',avi:'[VID]',mov:'[VID]',wmv:'[VID]',webm:'[VID]',
    mp3:'[SND]',flac:'[SND]',wav:'[SND]',ogg:'[SND]',aac:'[SND]',
    zip:'ARC',tar:'ARC',gz:'ARC',bz2:'ARC',xz:'ARC',rar:'ARC',
    pdf:'PDF',
    xls:'XLS',xlsx:'XLS',csv:'XLS',
    doc:'DOC',docx:'DOC',
  };
  var extra = {
    ARC:{e:'&#x1F4E6;', bg:'#fff3e0', c:'#f97316'},
    PDF:{e:'&#x1F4D5;', bg:'#fef2f2', c:'#ef4444'},
    XLS:{e:'&#x1F4CA;', bg:'#f0fdf4', c:'#16a34a'},
    DOC:{e:'&#x1F4DD;', bg:'#f0f3ff', c:'#4f6ef7'},
  };
  var fallback = {e:'&#x1F4C4;', bg:'#f0f3ff', c:'#4f6ef7'};

  document.querySelectorAll('table tr').forEach(function (row) {
    // classify row
    if (!row.querySelector('td')) {
      row.className = row.querySelector('hr') ? 'sep' : 'hdr';
      return;
    }
    row.className = 'row';

    var img  = row.querySelector('img');
    var link = row.querySelector('td a');
    if (!img || !link) return;

    var alt  = img.getAttribute('alt') || '';
    var ext  = link.textContent.trim().split('.').pop().toLowerCase();
    var key  = byExt[ext] || alt.trim();
    var ico  = extra[key] || byAlt[key] || fallback;

    var span = document.createElement('span');
    span.className = 'f-icon';
    span.style.cssText = 'background:' + ico.bg + ';color:' + ico.c;
    span.innerHTML = ico.e;

    var wrap = document.createElement('div');
    wrap.className = 'file-name';
    wrap.appendChild(span);
    wrap.appendChild(link);

    var firstTd = row.querySelector('td');
    firstTd.innerHTML = '';
    firstTd.appendChild(wrap);
  });
})();
</script>
</body>
</html>
'''
        self._write(os.path.join(ui_dir, 'header.html'), header)
        self._write(os.path.join(ui_dir, 'footer.html'), footer)

    # ----------------------------------------------------------------- FTP config
    def _apply_ftp_config(self, shares, nas_host=''):
        ftp_shares = [s for s in shares if 'ftp' in self._protocols(s)]
        public_ftp = [s for s in ftp_shares if s.get('public', 0)]
        has_public = bool(public_ftp)

        lines = [
            'listen=YES',
            'listen_ipv6=NO',
            f'anonymous_enable={"YES" if has_public else "NO"}',
            'local_enable=YES',
            'write_enable=YES',
            'local_umask=022',
            'dirmessage_enable=YES',
            'use_localtime=YES',
            'xferlog_enable=YES',
            'connect_from_port_20=YES',
            'chroot_local_user=YES',
            'local_root=/data/shares',
            'allow_writeable_chroot=YES',
            'secure_chroot_dir=/var/run/vsftpd/empty',
            'pam_service_name=vsftpd',
            'pasv_enable=YES',
            'pasv_min_port=21100',
            'pasv_max_port=21110',
            'userlist_enable=NO',
            'user_config_dir=/etc/vsftpd/users',
            'check_shell=NO',
        ]

        if has_public:
            # Single public share → land directly in it; multiple → show all under SHARES_DIR
            anon_root = public_ftp[0]['path'] if len(public_ftp) == 1 else SHARES_DIR
            lines += [
                'no_anon_password=YES',
                f'anon_root={anon_root}',
            ]

        # nas_host comes from request.host (the IP the browser used to reach the UI);
        # NAS_HOST env is the fallback for startup/seed where no request is available
        pasv_address = _safe(nas_host or os.environ.get('NAS_HOST', ''), 253)
        if pasv_address and re.match(r'^[A-Za-z0-9_.\-]{1,253}$', pasv_address):
            lines.append(f'pasv_address={pasv_address}')

        self._write('/etc/vsftpd.conf', '\n'.join(lines) + '\n')

    # ---------------------------------------------------------------- FTP peruser
    def _apply_ftp_users(self, users):
        userdir = '/etc/vsftpd/users'
        os.makedirs(userdir, exist_ok=True)
        for fname in os.listdir(userdir):
            os.remove(os.path.join(userdir, fname))
        for u in users:
            # Home must be /data/shares so chroot_local_user jails users there, not in /data/homes
            subprocess.run(['usermod', '-d', '/data/shares', u['username']],
                           check=False, capture_output=True)
            if not u.get('enabled', 1):
                # System account is locked via usermod -L; vsftpd rejects via PAM
                continue
            if u.get('readonly', 0):
                with open(os.path.join(userdir, u['username']), 'w') as f:
                    f.write('write_enable=NO\n')
        subprocess.run(['pkill', '-HUP', 'vsftpd'], check=False, capture_output=True)

    # --------------------------------------------------------------- SFTP peruser
    def _apply_sftp_users(self, users):
        lines = []
        for u in users:
            if u.get('readonly', 0) and u.get('enabled', 1):
                lines += [
                    f"Match User {u['username']}",
                    '    ChrootDirectory /data/shares',
                    '    ForceCommand internal-sftp -R',
                    '    AllowTcpForwarding no',
                    '    X11Forwarding no',
                    '',
                ]
        os.makedirs('/etc/ssh/sshd_config.d', exist_ok=True)
        self._write('/etc/ssh/sshd_config.d/nas-readonly.conf', '\n'.join(lines))
        subprocess.run(['pkill', '-HUP', 'sshd'], check=False, capture_output=True)

    # ------------------------------------------------------- Avahi / Time Machine
    def _apply_avahi_timemachine(self, shares):
        avahi_dir = '/etc/avahi/services'
        service_file = os.path.join(avahi_dir, 'timemachine.service')

        tm_shares = [s for s in shares if s.get('timemachine', 0) and 'smb' in self._protocols(s)]

        if not tm_shares:
            if os.path.exists(service_file):
                os.remove(service_file)
                subprocess.run(['pkill', '-HUP', 'avahi-daemon'], check=False, capture_output=True)
            return

        os.makedirs(avahi_dir, exist_ok=True)

        dk_records = '\n'.join(
            f'    <txt-record>dk{i}=adVN={_safe(s.get("name", ""), 64)},adVF=0x82</txt-record>'
            for i, s in enumerate(tm_shares)
        )

        xml = (
            "<?xml version=\"1.0\" standalone='no'?>\n"
            "<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">\n"
            "<service-group>\n"
            "  <name replace-wildcards=\"yes\">%h</name>\n"
            "  <service>\n"
            "    <type>_smb._tcp</type>\n"
            "    <port>445</port>\n"
            "  </service>\n"
            "  <service>\n"
            "    <type>_device-info._tcp</type>\n"
            "    <port>0</port>\n"
            "    <txt-record>model=TimeCapsule8,119</txt-record>\n"
            "  </service>\n"
            "  <service>\n"
            "    <type>_adisk._tcp</type>\n"
            "    <port>9</port>\n"
            f"{dk_records}\n"
            "    <txt-record>sys=waMa=0,adVF=0x100</txt-record>\n"
            "  </service>\n"
            "</service-group>\n"
        )
        self._write(service_file, xml)
        subprocess.run(['pkill', '-HUP', 'avahi-daemon'], check=False, capture_output=True)

    # ---------------------------------------------------- WebDAV portal page
    def _apply_portal(self, shares):
        webdav_shares = [s for s in shares if 'webdav' in self._protocols(s)]

        if webdav_shares:
            cards_html = '\n'.join(
                f'''        <a href="/{s['name']}/" class="share-card">
          <div class="share-icon"><svg width="28" height="28" fill="none" viewBox="0 0 24 24"><path fill="currentColor" d="M3 6a3 3 0 0 1 3-3h12a3 3 0 0 1 3 3v12a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V6Zm3-1a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1H6Zm1 3h10v2H7V8Zm0 4h7v2H7v-2Z"/></svg></div>
          <div class="share-info">
            <div class="share-name">{s['name']}</div>
            <div class="share-desc">{s.get('comment', '') or 'WebDAV share'}</div>
          </div>
          <div class="share-arrow">→</div>
        </a>'''
                for s in webdav_shares
            )
            files_section = f'''
      <section>
        <h2 class="section-title"><span class="dot"></span>WebDAV Shares</h2>
        <div class="cards">
{cards_html}
        </div>
      </section>'''
        else:
            files_section = '''
      <section>
        <h2 class="section-title"><span class="dot"></span>WebDAV Shares</h2>
        <div class="empty-state">No WebDAV shares configured yet.<br>Add a share with WebDAV enabled in the <a href="#" id="new-share-link">management UI</a>.</div>
        <script>document.getElementById('new-share-link').href='http://'+location.hostname+':8080/shares/new';</script>
      </section>'''

        html = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Coshic NAS</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f4f5fb; color: #1e2030; min-height: 100vh; }

  /* Header */
  header { background: #13152a; color: #fff; padding: 0 32px;
           display: flex; align-items: center; justify-content: space-between;
           height: 64px; box-shadow: 0 2px 16px rgba(0,0,0,.35); }
  .brand { display: flex; align-items: center; gap: 12px; font-size: 18px; font-weight: 700; }
  .brand-icon { width: 36px; height: 36px; background: #4f6ef7; border-radius: 10px;
                display: flex; align-items: center; justify-content: center; font-size: 20px; }
  .manage-btn { background: #4f6ef7; color: #fff; border: none; border-radius: 8px;
                padding: 8px 18px; font-size: 13px; font-weight: 600; cursor: pointer;
                text-decoration: none; transition: background .15s; white-space: nowrap; }
  .manage-btn:hover { background: #3d5ae6; }

  /* Layout */
  main { max-width: 920px; margin: 0 auto; padding: 40px 20px 60px; }

  /* Section */
  .section-title { font-size: 11px; font-weight: 700; text-transform: uppercase;
                   letter-spacing: .6px; color: #8890a4; margin-bottom: 14px;
                   display: flex; align-items: center; gap: 8px; }
  .dot { width: 6px; height: 6px; border-radius: 50%; background: #4f6ef7; display: inline-block; }
  section { margin-bottom: 40px; }

  /* Share cards */
  .cards { display: flex; flex-direction: column; gap: 8px; }
  .share-card { background: #fff; border: 1px solid #e8eaf0; border-radius: 12px;
                padding: 16px 20px; display: flex; align-items: center; gap: 16px;
                text-decoration: none; color: inherit;
                transition: border-color .15s, box-shadow .15s; }
  .share-card:hover { border-color: #4f6ef7; box-shadow: 0 2px 12px rgba(79,110,247,.12); }
  .share-icon { width: 44px; height: 44px; background: #edf0ff; border-radius: 10px;
                display: flex; align-items: center; justify-content: center; color: #4f6ef7; flex-shrink: 0; }
  .share-name { font-weight: 600; font-size: 14px; }
  .share-desc { font-size: 12px; color: #8890a4; margin-top: 2px; }
  .share-info { flex: 1; }
  .share-arrow { color: #c0c6d8; font-size: 18px; }
  .share-card:hover .share-arrow { color: #4f6ef7; }
  .empty-state { background: #fff; border: 1px solid #e8eaf0; border-radius: 12px;
                 padding: 32px; text-align: center; color: #8890a4; font-size: 13px;
                 line-height: 1.7; }
  .empty-state a { color: #4f6ef7; }

  /* Connect grid */
  .connect-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
  .connect-card { background: #fff; border: 1px solid #e8eaf0; border-radius: 12px; padding: 20px; }
  .connect-card h3 { font-size: 13px; font-weight: 700; margin-bottom: 12px;
                     display: flex; align-items: center; gap: 8px; }
  .connect-card h3 .badge { font-size: 10px; font-weight: 600; padding: 2px 8px;
                             border-radius: 20px; }
  .step { font-size: 12px; color: #4a5168; margin-bottom: 8px; line-height: 1.5; }
  .step:last-child { margin-bottom: 0; }
  .step strong { display: block; color: #1e2030; margin-bottom: 2px; }
  code { background: #f0f3ff; color: #4f6ef7; padding: 1px 6px;
         border-radius: 4px; font-size: 11.5px; font-family: monospace;
         word-break: break-all; overflow-wrap: break-word; }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-icon"><svg width="22" height="22" fill="white" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 0-2 2v1a2 2 0 0 0 2 2h5.5v3A1.5 1.5 0 0 0 6 11.5H.5a.5.5 0 0 0 0 1H6A1.5 1.5 0 0 0 7.5 14h1a1.5 1.5 0 0 0 1.5-1.5h5.5a.5.5 0 0 0 0-1H10A1.5 1.5 0 0 0 8.5 10V7H14a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zm.5 3a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m2 0a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1M14.5 5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1"/></svg></div>
    <span>Coshic NAS</span>
  </div>
  <a href="#" id="manage-link" class="manage-btn">⚙ Manage</a>
  <script>document.getElementById('manage-link').href='http://'+location.hostname+':8080';</script>
</header>

<main>
''' + files_section + '''

  <section>
    <h2 class="section-title"><span class="dot"></span>INFO: How to connect to shares</h2>
    <div class="connect-grid">

      <div class="connect-card">
        <h3><svg width="15" height="15" fill="currentColor" viewBox="0 0 16 16" style="flex-shrink:0"><path d="M0 4s0-2 2-2h12s2 0 2 2v6s0 2-2 2h-4q0 1 .25 1.5H11a.5.5 0 0 1 0 1H5a.5.5 0 0 1 0-1h.75Q6 13 6 12H2s-2 0-2-2zm1.398-.855a.76.76 0 0 0-.254.302A1.46 1.46 0 0 0 1 4.01V10c0 .325.078.502.145.602.07.105.17.188.302.254a1.5 1.5 0 0 0 .538.143L2.01 11H14c.325 0 .502-.078.602-.145a.76.76 0 0 0 .254-.302 1.46 1.46 0 0 0 .143-.538L15 9.99V4c0-.325-.078-.502-.145-.602a.76.76 0 0 0-.302-.254A1.46 1.46 0 0 0 13.99 3H2c-.325 0-.502.078-.602.145z"/></svg> Windows <span class="badge" style="background:#e8ecff;color:#4f6ef7">SMB</span></h3>
        <div class="step"><strong>File Explorer</strong>In the address bar type:<br><code>\\\\{{HOST}}\\share-name</code></div>
        <div class="step"><strong>Map Network Drive</strong>Right-click This PC → Map network drive → enter the path above</div>
      </div>

      <div class="connect-card">
        <h3>🍎 macOS <span class="badge" style="background:#e8ecff;color:#4f6ef7">SMB</span></h3>
        <div class="step"><strong>Finder</strong>Press <code>⌘K</code> and enter:<br><code>smb://{{HOST}}/share-name</code></div>
        <div class="step"><strong>Time Machine</strong>Connect first, then System Settings → Time Machine → Add Backup Disk</div>
      </div>

      <div class="connect-card">
        <h3>🐧 Linux <span class="badge" style="background:#fff3cd;color:#856404">NFS / SMB</span></h3>
        <div class="step"><strong>NFS mount</strong><code>mount -t nfs {{HOST}}:/data/shares/name /mnt/nas</code></div>
        <div class="step"><strong>SMB via CLI</strong><code>smbclient //{{HOST}}/share-name</code></div>
      </div>

      <div class="connect-card">
        <h3>☁ WebDAV <span class="badge" style="background:#f3e8ff;color:#7c3aed">HTTP</span></h3>
        <div class="step"><strong>Browser / File manager</strong>Open a share directly - the links above take you straight to the files</div>
        <div class="step"><strong>URL format</strong><code>http://{{HOST}}/share-name/</code></div>
      </div>

      <div class="connect-card">
        <h3>🔒 SFTP <span class="badge" style="background:#dcfce7;color:#166534">SSH</span></h3>
        <div class="step"><strong>Command line</strong><code>sftp -P 2222 user@{{HOST}}</code></div>
        <div class="step"><strong>GUI clients</strong>FileZilla, Cyberduck - use port <code>2222</code></div>
      </div>

      <div class="connect-card">
        <h3>📁 FTP <span class="badge" style="background:#cffafe;color:#0e7490">FTP</span></h3>
        <div class="step"><strong>URL</strong><code>ftp://{{HOST}}</code></div>
        <div class="step"><strong>GUI clients</strong>FileZilla, WinSCP - active port <code>21</code>, passive <code>21100–21110</code></div>
      </div>

    </div>
  </section>
</main>

</body>
</html>
'''

        nas_host = _safe(os.environ.get('NAS_HOST', 'nas-server'), 253)
        html = html.replace('{{HOST}}', nas_host)
        self._write('/var/www/html/index.html', html)

    # --------------------------------------------------------- Service status
    def get_service_statuses(self):
        ssh_port = os.environ.get('NAS_SSH_PORT', '22')
        services = [
            {'name': 'SMB/CIFS',  'proc': 'smbd',      'protocol': 'smb',    'port': 445},
            {'name': 'NFS',       'proc': 'rpc.mountd', 'protocol': 'nfs',    'port': 2049},
            {'name': 'FTP',       'proc': 'vsftpd',     'protocol': 'ftp',    'port': 21},
            {'name': 'SFTP/SSH',  'proc': 'sshd',       'protocol': 'sftp',   'port': ssh_port},
            {'name': 'WebDAV',    'proc': 'apache2',    'protocol': 'webdav', 'port': '80/443'},
        ]
        for svc in services:
            r = subprocess.run(['pgrep', '-x', svc['proc']], capture_output=True)
            svc['running'] = (r.returncode == 0)
        return services

    # ----------------------------------------------------------------- Utils
    @staticmethod
    def _protocols(share):
        raw = share.get('protocols', '[]')
        try:
            return json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            return []

    @staticmethod
    def _access(share):
        raw = share.get('access_list', '[]')
        try:
            return json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            return []

    @staticmethod
    def _write(path, content):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
