#!/bin/bash
# User-space NFS startup wrapper for supervisor

cleanup() {
    # Tell the kernel NFS server to wind down (0 threads = graceful stop)
    rpc.nfsd 0 2>/dev/null || true
    exportfs -ua 2>/dev/null || true
    pkill -x rpc.statd  2>/dev/null || true
    pkill -x rpcbind    2>/dev/null || true
    [ -n "$MOUNTD_PID" ] && kill "$MOUNTD_PID" 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

# Start rpcbind
rpcbind -w 2>/dev/null || true
sleep 1

# Start statd
rpc.statd 2>/dev/null || true
sleep 1

# Load current exports
exportfs -ra 2>/dev/null || true

# Start NFS daemon (8 threads)
rpc.nfsd 8 2>/dev/null || true
sleep 1

# Run mountd in background so the bash process stays alive to handle signals
rpc.mountd --foreground --port 20048 2>&1 &
MOUNTD_PID=$!
wait $MOUNTD_PID
