FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    samba \
    samba-common \
    samba-common-bin \
    samba-vfs-modules \
    avahi-daemon \
    avahi-utils \
    libnss-mdns \
    nfs-kernel-server \
    nfs-common \
    rpcbind \
    vsftpd \
    openssh-server \
    apache2 \
    apache2-utils \
    python3 \
    python3-pip \
    python3-venv \
    supervisor \
    openssl \
    ssl-cert \
    procps \
    passwd \
    util-linux \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt .
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Download frontend vendor assets at build time so the container runs fully offline.
# Each download is logged with its SHA-256 so build output can be audited for
# unexpected changes from the upstream CDN. To enforce verification, copy the
# expected hashes into vendor-assets.sha256 (one "<sha256>  <path>" per line)
# and the build will fail on mismatch.
COPY app/vendor-assets.sha256 /tmp/vendor-assets.sha256
RUN mkdir -p static/vendor/bootstrap \
             static/vendor/bootstrap-icons/fonts && \
    set -eu && \
    curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" \
         -o static/vendor/bootstrap/bootstrap.min.css && \
    curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" \
         -o static/vendor/bootstrap/bootstrap.bundle.min.js && \
    curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" \
         -o static/vendor/bootstrap-icons/bootstrap-icons.css && \
    curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff2" \
         -o static/vendor/bootstrap-icons/fonts/bootstrap-icons.woff2 && \
    curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff" \
         -o static/vendor/bootstrap-icons/fonts/bootstrap-icons.woff && \
    echo "=== Vendor asset SHA-256 (audit me) ===" && \
    (cd static && sha256sum \
        vendor/bootstrap/bootstrap.min.css \
        vendor/bootstrap/bootstrap.bundle.min.js \
        vendor/bootstrap-icons/bootstrap-icons.css \
        vendor/bootstrap-icons/fonts/bootstrap-icons.woff2 \
        vendor/bootstrap-icons/fonts/bootstrap-icons.woff) && \
    if [ -s /tmp/vendor-assets.sha256 ]; then \
        echo "=== Verifying against pinned hashes ===" && \
        (cd static && sha256sum -c /tmp/vendor-assets.sha256); \
    else \
        echo "WARNING: vendor-assets.sha256 is empty - assets are NOT pinned." \
             "Run the build once, copy the SHA-256 lines from above into" \
             "app/vendor-assets.sha256, then rebuild to enable verification." >&2; \
    fi

COPY supervisord.conf /etc/supervisor/conf.d/nas.conf
COPY apache-webdav.conf /etc/apache2/sites-available/nas-webdav.conf
COPY scripts/run-nfs.sh /usr/local/bin/run-nfs.sh
COPY scripts/apply-services.sh /usr/local/bin/apply-services.sh
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/run-nfs.sh /usr/local/bin/apply-services.sh

RUN mkdir -p /data/shares /data/config /data/homes \
    /var/run/samba /var/log/samba \
    /var/run/vsftpd/empty \
    /var/run/sshd \
    /var/log/supervisor

RUN a2enmod dav dav_fs dav_lock auth_basic authn_file ssl headers && \
    a2dissite 000-default && \
    a2ensite nas-webdav

EXPOSE 8080 21 20 22 139 445 2049 80 443 21100-21110

ENTRYPOINT ["/entrypoint.sh"]
