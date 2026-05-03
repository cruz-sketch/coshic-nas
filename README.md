# Coshic NAS

A self-hosted NAS server running in Docker with a web-based management UI. Supports multiple file-sharing protocols, user access control, and macOS Time Machine backups.

**→ [github.com/cruz-sketch/coshic-nas](https://github.com/cruz-sketch/coshic-nas)**

## Features

- **Web UI** - manage shares and users from a browser (port 8080)
- **SMB/CIFS** - Windows, macOS, Linux (port 445)
- **NFS** - Linux/Unix (port 2049)
- **FTP** - classic FTP with passive mode (port 21)
- **SFTP** - secure file transfer over SSH (port 2222)
- **WebDAV** - HTTP/HTTPS access with browser file listing (ports 80/443)
  - Per-share toggle: open files inline in browser or force download
  - Custom SSL certificate upload via web UI
- **Time Machine** - macOS backup destination via SMB with Bonjour/mDNS advertising
- Per-user read/write permissions and enable/disable controls
- Public (guest) and private (password-protected) shares
- **First-start seeding** - declare users and shares via environment variables; created automatically on first boot

## Quick Start

```bash
git clone https://github.com/cruz-sketch/coshic-nas
cd coshic-nas
docker compose up -d --build
```

Open `http://localhost:8080` - default password: **admin**

## Configuration

All settings are managed through the web UI. Environment variables can be set in `docker-compose.yml`:

| Variable | Description |
|---|---|
| `LOGIN_PASSWORD` | Initial web UI password (change via Settings after first login) |
| `NAS_HOST` | Your server's LAN IP (e.g. `192.168.1.100`). Required for FTP passive mode in Docker bridge networking - Docker cannot auto-detect the host IP from inside the container. Also shown in the "Connection Paths" dialog in the UI. |
| `NAS_USERS` | Seed users on first startup - see [First-Start Seeding](#first-start-seeding) |
| `NAS_SHARES` | Seed shares on first startup - see [First-Start Seeding](#first-start-seeding) |

## First-Start Seeding

Users and shares can be declared as environment variables and will be created automatically when the container first starts. On subsequent restarts, existing entries are skipped - the seed is fully idempotent.

### Users - `NAS_USERS`

Format: entries separated by ` | `, each entry is `username:password` or `username:password:ro` for a read-only user.

```yaml
NAS_USERS: "alice:secret | bob:pass:ro"
```

| Field | Required | Description |
|---|---|---|
| `username` | yes | Login name |
| `password` | yes | Initial password |
| `ro` | no | Read-only access across all protocols |

### Shares - `NAS_SHARES`

Format: entries separated by ` | `, each entry is `name:protocols:flags:users`.

```yaml
NAS_SHARES: "movies:smb,ftp:public | documents:smb,nfs::alice,bob=ro | backups:smb:timemachine:alice"
```

| Field | Required | Description |
|---|---|---|
| `name` | yes | Share name - letters, digits, hyphens, underscores |
| `protocols` | no | Comma-separated: `smb`, `nfs`, `ftp`, `sftp`, `webdav` (default: `smb`) |
| `flags` | no | Comma-separated - see table below |
| `users` | no | Comma-separated: `username` (rw) or `username=ro` |

**Available flags:**

| Flag | Description |
|---|---|
| `public` | No authentication required (guest access) |
| `timemachine` | Advertise as macOS Time Machine destination (requires SMB) |
| `no-aio` | Disable async I/O and sendfile (enabled by default for SMB) |
| `sync-writes` | Force fsync on every write - safer but slower |

If you have no flags but want to set users, leave the flags field empty:

```yaml
NAS_SHARES: "documents:smb,nfs::alice,bob=ro"
#                             ^^ empty flags field
```

The share directory is created at `/data/shares/<name>` with the correct permissions. After seeding, all shares and users are fully editable through the web UI.

## Time Machine (macOS Backup)

1. Edit or create a share, enable **SMB** protocol, and check **Time Machine target**
2. On your Mac: Finder → `⌘K` → `smb://<NAS-IP>` → connect with your NAS user credentials
3. System Settings → Time Machine → Add Backup Disk → select the connected share

### Auto-discovery via Bonjour

For the NAS to appear **automatically** in Time Machine without manually connecting first, mDNS/Bonjour must reach your local network. Docker's bridge networking blocks multicast by default.

**To enable auto-discovery**, switch to host networking in `docker-compose.yml`:

```yaml
services:
  nas:
    network_mode: host   # add this
    # ports:             # remove or comment out the entire ports section
    #   - "8080:8080"    # (not needed in host mode - all ports are exposed directly)
    #   - ...
```

> **Windows note:** Port 445 (SMB) may be in use by Windows itself. Run `sc stop lanmanserver` in an elevated command prompt before starting the container if you get a port conflict.

Without host networking, Time Machine still works - you just need to connect to the server manually in Finder first (step 2 above).

## SMB Performance

Each SMB share has per-share performance settings available under **Advanced performance settings** in the share form (collapsed by default):

| Setting | Default | Description |
|---|---|---|
| **Async I/O & sendfile** | On | Uses kernel `sendfile()` and async I/O for faster large-file transfers. No data-loss risk. |
| **Force sync on write** | Off | Calls `fsync()` after every write. Protects against data loss on sudden power failure at the cost of write throughput. |

Additionally, `TCP_NODELAY` is set globally for all SMB connections to reduce latency on small operations.

## WebDAV

WebDAV shares are accessible via browser at `http://<host>/<share-name>/`. The root page at `http://<host>/` lists all WebDAV shares and connection instructions. The **WebDAV** button in the dashboard header links directly to that portal when the service is enabled.

HTTPS is available at port 443 with a self-signed certificate generated on first start.

### File opening behaviour

Each WebDAV share has a **Browser preview (inline)** toggle in the share settings (WebDAV Options section):

| Setting | Description |
|---|---|
| **On** (default) | Files open directly in the browser - images, PDFs, video, text show inline |
| **Off** | Every file click triggers a download regardless of file type |

### Custom SSL certificate

To replace the auto-generated self-signed certificate, edit any WebDAV share and expand **Advanced - HTTPS Certificate**. Upload your `.crt` and `.key` files - Apache reloads immediately and the certificate applies to all WebDAV shares on port 443.

## Protocols & Ports

| Protocol | Port | Notes |
|---|---|---|
| Web UI | 8080 | Management interface |
| SMB | 445, 139 | Windows/macOS file sharing |
| NFS | 2049 | Linux/Unix file sharing |
| FTP | 21, 20, 21100–21110 | Active + passive mode |
| SFTP | 2222 | Mapped to container port 22 |
| WebDAV | 80, 443 | HTTPS uses a self-signed cert by default |
| mDNS | 5353/udp | Bonjour for Time Machine (see above) |

## Data Volumes

| Volume | Mount | Contents |
|---|---|---|
| `nas_data` | `/data/shares` | All shared files |
| `nas_config` | `/data/config` | Database, certificates, service configs |
| `nas_homes` | `/data/homes` | User home directories |

## Tech Stack

- **Backend:** Python / Flask / Gunicorn
- **Services:** Samba, NFS (nfs-kernel-server), vsftpd, OpenSSH, Apache2 (WebDAV), avahi-daemon
- **Process manager:** Supervisor
- **Base image:** `debian:trixie-slim`
