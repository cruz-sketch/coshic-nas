#!/bin/bash
# Runs once at startup via supervisor to restore enabled/disabled service states.

# Wait until supervisorctl can connect (max 30 s)
for i in $(seq 1 30); do
    supervisorctl status >/dev/null 2>&1 && break
    sleep 1
done

SERVICES_FILE=/data/config/services.json
[ -f "$SERVICES_FILE" ] || exit 0

python3 - << 'EOF'
import json, subprocess

PROGRAMS = {
    'smb':    ['samba-smbd', 'samba-nmbd'],
    'nfs':    ['nfs'],
    'ftp':    ['vsftpd'],
    'sftp':   ['sshd'],
    'webdav': ['apache2'],
}

try:
    with open('/data/config/services.json') as f:
        states = json.load(f)
except Exception:
    exit(0)

for svc, enabled in states.items():
    for prog in PROGRAMS.get(svc, []):
        cmd = 'start' if enabled else 'stop'
        subprocess.run(['supervisorctl', cmd, prog], capture_output=True)
EOF
