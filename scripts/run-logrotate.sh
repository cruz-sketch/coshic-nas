#!/bin/sh
# Daily logrotate runner. Supervisord keeps it alive; we sleep between passes.
# A short delay on first iteration prevents racing with apache/samba startup.

set -u

CONF=/etc/logrotate.d/coshic.conf
STATE=/var/lib/logrotate/coshic.status

mkdir -p /var/lib/logrotate

sleep 60

while true; do
    /usr/sbin/logrotate -s "$STATE" "$CONF" || true
    # Run once a day. If the container is short-lived, that's fine - the rules
    # also kick in on size, not just age.
    sleep 86400
done
