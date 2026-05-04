#!/usr/bin/env python3
"""
Seed users and shares from environment variables on first container startup.

NAS_USERS  - pipe-separated list of "username:password[:ro]"
NAS_SHARES - pipe-separated list of "name[:protocols[:flags]]"
             protocols : comma-separated - smb,nfs,ftp,sftp,webdav  (default: smb)
             flags     : comma-separated - public,timemachine,no-aio,sync-writes

Example:
  NAS_USERS:  "alice:secret | bob:pass:ro"
  NAS_SHARES: "movies:smb,ftp:public | documents:smb,nfs | backups:smb:timemachine"
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, '/app')
from database import Database
from config_generator import ConfigGenerator

_USER_RE  = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')
_SHARE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


def _parse_users(raw):
    result = []
    for part in raw.split('|'):
        fields = [f.strip() for f in part.strip().split(':')]
        if len(fields) < 2 or not fields[0]:
            continue
        result.append({
            'username': fields[0],
            'password': fields[1],
            'readonly': len(fields) > 2 and 'ro' in fields[2:],
        })
    return result


def _parse_shares(raw):
    result = []
    for part in raw.split('|'):
        fields = [f.strip() for f in part.strip().split(':')]
        if not fields[0]:
            continue
        protocols = [p.strip() for p in fields[1].split(',')] if len(fields) > 1 and fields[1] else ['smb']
        flags     = [f.strip() for f in fields[2].split(',')] if len(fields) > 2 and fields[2] else []

        access_list = []
        if len(fields) > 3 and fields[3]:
            for entry in fields[3].split(','):
                entry = entry.strip()
                if '=' in entry:
                    uname, level = entry.split('=', 1)
                    access_list.append({'username': uname.strip(), 'access': level.strip()})
                elif entry:
                    access_list.append({'username': entry, 'access': 'rw'})

        result.append({
            'name':            fields[0],
            'protocols':       protocols,
            'public':          1 if 'public'      in flags else 0,
            'timemachine':     1 if 'timemachine'  in flags else 0,
            'smb_async_io':    0 if 'no-aio'       in flags else 1,
            'smb_sync_writes': 1 if 'sync-writes'  in flags else 0,
            'access_list':     access_list,
        })
    return result


def _create_system_user(username, password):
    if not _USER_RE.match(username):
        raise ValueError(f'invalid username: {username!r}')
    subprocess.run(
        ['useradd', '-s', '/usr/sbin/nologin', '-d', '/data/shares', '-G', 'nasusers', username],
        capture_output=True,
    )
    result = subprocess.run(
        ['openssl', 'passwd', '-6', '-stdin'],
        input=password, capture_output=True, text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        subprocess.run(['usermod', '-p', result.stdout.strip(), username], capture_output=True)
    else:
        p = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate(input=f'{username}:{password}\n'.encode())

    subprocess.run(['smbpasswd', '-x', username], capture_output=True)
    p = subprocess.Popen(
        ['smbpasswd', '-a', '-s', username],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    p.communicate(input=f'{password}\n{password}\n'.encode())
    subprocess.run(['smbpasswd', '-e', username], capture_output=True)

    # WebDAV: pipe password via stdin so it never appears in `ps` output
    config_dir = os.environ.get('CONFIG_DIR', '/data/config')
    htpasswd = f'{config_dir}/webdav.passwords'
    if not os.path.exists(htpasswd):
        fd = os.open(htpasswd, os.O_WRONLY | os.O_CREAT, 0o640)
        os.close(fd)
    p = subprocess.Popen(
        ['htpasswd', '-i', htpasswd, username],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    p.communicate(input=password.encode())
    try:
        os.chmod(htpasswd, 0o640)
    except Exception:
        pass


def main():
    nas_users  = os.environ.get('NAS_USERS',  '').strip()
    nas_shares = os.environ.get('NAS_SHARES', '').strip()

    if not nas_users and not nas_shares:
        return

    db  = Database()
    cfg = ConfigGenerator(db)
    changed = False

    if nas_users:
        existing = {u['username'] for u in db.get_all_users()}
        for u in _parse_users(nas_users):
            if not _USER_RE.match(u['username']):
                print(f"[seed] user '{u['username']}' has invalid name, skipping",
                      file=sys.stderr)
                continue
            if u['username'] in existing:
                print(f"[seed] user '{u['username']}' already exists, skipping")
                continue
            print(f"[seed] creating user '{u['username']}'")
            db.create_user(u['username'], readonly=u['readonly'])
            _create_system_user(u['username'], u['password'])
            changed = True

    if nas_shares:
        existing = {s['name'] for s in db.get_all_shares()}
        for s in _parse_shares(nas_shares):
            if not _SHARE_RE.match(s['name']):
                print(f"[seed] share '{s['name']}' has invalid name, skipping",
                      file=sys.stderr)
                continue
            if s['name'] in existing:
                print(f"[seed] share '{s['name']}' already exists, skipping")
                continue
            print(f"[seed] creating share '{s['name']}'")
            path = f"/data/shares/{s['name']}"
            db.create_share({
                'name':            s['name'],
                'path':            path,
                'comment':         '',
                'protocols':       json.dumps(s['protocols']),
                'public':          s['public'],
                'smb_guest_write': 0,
                'nfs_hosts':       '*',
                'nfs_options':     'rw,sync,no_subtree_check,root_squash',
                'access_list':     json.dumps(s['access_list']),
                'timemachine':     s['timemachine'],
                'smb_async_io':    s['smb_async_io'],
                'smb_sync_writes': s['smb_sync_writes'],
                'webdav_inline_preview': 1,
            })
            os.makedirs(path, exist_ok=True)
            try:
                os.chmod(path, 0o775)
                subprocess.run(['chown', 'root:nasusers', path], capture_output=True)
            except Exception:
                pass
            changed = True

    if changed:
        try:
            cfg.apply_all()
        except Exception as e:
            print(f"[seed] apply_all warning: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
