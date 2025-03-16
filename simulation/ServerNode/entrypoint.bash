#!/usr/bin/env bash

graceful_shutdown() {
    echo "Termination signal received. Shutting down NFS services..."
    umount /mnt/nfs/tier1 || echo 'Unmount tier1 failed'
    umount /mnt/nfs/tier2 || echo 'Unmount tier2 failed'
    umount /mnt/nfs/tier3 || echo 'Unmount tier3 failed'
    exit 0
}

trap graceful_shutdown SIGTERM SIGINT

mkdir -p /mnt/nfs/tier1 /mnt/nfs/tier2 /mnt/nfs/tier3
echo 'Waiting for storage_tier1...'
while ! ping -c 1 storage_tier1 > /dev/null 2>&1; do sleep 1; done
echo 'Waiting for storage_tier2...' && \
while ! ping -c 1 storage_tier2 > /dev/null 2>&1; do sleep 1; done
echo 'Waiting for storage_tier3...' && \
while ! ping -c 1 storage_tier3 > /dev/null 2>&1; do sleep 1; done 

mount -o nolock -t nfs storage_tier1:/mnt/tier /mnt/nfs/tier1 || echo 'Mount tier1 failed'
echo 'Mount tier1 success'
mount -o nolock -t nfs storage_tier2:/mnt/tier /mnt/nfs/tier2 || echo 'Mount tier2 failed'
echo 'Mount tier2 success'
mount -o nolock -t nfs storage_tier3:/mnt/tier /mnt/nfs/tier3 || echo 'Mount tier3 failed'
echo 'Mount tier3 success'


while true; do sleep 1; done
