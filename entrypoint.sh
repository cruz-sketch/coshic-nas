#!/bin/bash
set -e

CONFIG_DIR=/data/config
SHARES_DIR=/data/shares
HOMES_DIR=/data/homes

mkdir -p "$CONFIG_DIR" "$SHARES_DIR" "$HOMES_DIR"
chmod 755 "$SHARES_DIR"

# --- SSH host keys ---
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi

# Append SFTP chroot config (idempotent)
if ! grep -q "ChrootDirectory /data/shares" /etc/ssh/sshd_config 2>/dev/null; then
    cat >> /etc/ssh/sshd_config << 'SSHEOF'

PasswordAuthentication yes
ChallengeResponseAuthentication no
PermitRootLogin no
UsePAM yes

Match Group nasusers
    ChrootDirectory /data/shares
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
SSHEOF
fi

# --- nasusers group ---
getent group nasusers > /dev/null 2>&1 || groupadd nasusers

# /data/shares must be root:root 755 for SFTP chroot
chown root:root /data/shares
chmod 755 /data/shares

# --- Samba ---
if [ ! -f /etc/samba/smb.conf ] || ! grep -q "NAS Server" /etc/samba/smb.conf; then
    cat > /etc/samba/smb.conf << 'SMBEOF'
[global]
   workgroup = WORKGROUP
   server string = Coshic NAS
   security = user
   map to guest = bad user
   log file = /var/log/samba/log.%m
   max log size = 1000
   dns proxy = no
SMBEOF
fi

# --- FTP (vsftpd) ---

# vsftpd rejects users whose shell is not in /etc/shells.
# Users we create use /usr/sbin/nologin which is absent by default on Debian.
grep -qxF '/usr/sbin/nologin' /etc/shells || echo '/usr/sbin/nologin' >> /etc/shells

# Override the PAM config: remove pam_loginuid.so which breaks inside Docker.
cat > /etc/pam.d/vsftpd << 'PAMEOF'
auth    required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
auth    required pam_unix.so
account required pam_unix.so
session required pam_unix.so
PAMEOF

PASV_ADDRESS=${PASV_ADDRESS:-}

cat > /etc/vsftpd.conf << EOF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
local_root=/data/shares
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=21100
pasv_max_port=21110
userlist_enable=NO
user_config_dir=/etc/vsftpd/users
check_shell=NO
EOF

mkdir -p /etc/vsftpd/users

if [ -n "$PASV_ADDRESS" ]; then
    echo "pasv_address=$PASV_ADDRESS" >> /etc/vsftpd.conf
fi

# --- Avahi / Bonjour for Time Machine discovery ---
mkdir -p /etc/avahi/services
cat > /etc/avahi/avahi-daemon.conf << 'AVAHIEOF'
[server]
use-ipv4=yes
use-ipv6=no
enable-dbus=no

[publish]
publish-addresses=yes
publish-hinfo=no
publish-workstation=no
publish-domain=yes
AVAHIEOF

# --- SSL cert for WebDAV HTTPS ---
SSL_DIR="$CONFIG_DIR/ssl"
mkdir -p "$SSL_DIR"
if [ ! -f "$SSL_DIR/server.crt" ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_DIR/server.key" \
        -out "$SSL_DIR/server.crt" \
        -subj "/CN=nas-server/O=NAS Server/C=UA" 2>/dev/null
fi

# --- WebDAV init file ---
if [ ! -f "$CONFIG_DIR/webdav.passwords" ]; then
    touch "$CONFIG_DIR/webdav.passwords"
fi

# Init empty apache-shares.conf so Include doesn't fail on first boot
[ -f "$CONFIG_DIR/apache-shares.conf" ] || touch "$CONFIG_DIR/apache-shares.conf"

# Init NAS DB (will be done by Flask on first run)
mkdir -p "$CONFIG_DIR"

# --- NFS: load kernel modules if available ---
modprobe nfs 2>/dev/null || true
modprobe nfsd 2>/dev/null || true

mkdir -p /proc/fs/nfsd 2>/dev/null || true
mount -t nfsd nfsd /proc/fs/nfsd 2>/dev/null || true

# Init exports
[ -f /etc/exports ] || touch /etc/exports

# --- mod_headers for WebDAV Content-Disposition support ---
a2enmod headers 2>/dev/null || true

# --- Apache log dir ---
mkdir -p /var/log/apache2 /var/run/apache2
chown -R www-data:www-data /var/log/apache2

# --- Supervisor socket dir ---
mkdir -p /var/run/supervisor

# --- Seed users and shares from environment variables ---
/app/venv/bin/python3 /app/seed.py

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
