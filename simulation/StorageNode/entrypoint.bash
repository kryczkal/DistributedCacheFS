#!/usr/bin/env bash
set -e

graceful_shutdown() {
    echo "Termination signal received. Shutting down NFS services..."
    pkill rpc.nfsd || true
    pkill rpc.mountd || true
    pkill rpcbind || true
    umount /mnt/tier || echo 'Unmount tier failed'
    umount /proc/fs/nfsd || echo 'Unmount nfsd failed'
    exit 0
}

trap graceful_shutdown SIGTERM SIGINT


echo "Mounting nfsd filesystem..."
mount -t nfsd nfsd /proc/fs/nfsd 2>/dev/null

mount --bind /mnt/raw /mnt/tier

if [ -n "$NETWORK_DELAY" ] && [ "$NETWORK_DELAY" != "0ms" ]; then
    echo "Applying network delay NETWORK_DELAY=$NETWORK_DELAY"
    tc qdisc add dev eth0 root netem delay $NETWORK_DELAY
fi

echo "Starting rpcbind..."
rpcbind

echo "Starting NFS server..."
rpc.nfsd

echo "Starting mount daemon..."
rpc.mountd

echo "Re-exporting NFS shares..."
exportfs -r

echo "NFS server started, container is running..."

while true; do sleep 1; done

