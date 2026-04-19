#!/bin/sh
set -e

# Create socket directory accessible by prysm group
mkdir -p /var/run/prysm
chown root:prysm /var/run/prysm
chmod 750 /var/run/prysm

# Start nethelper as root (stays in background)
/app/prysm-nethelper &
NETHELPER_PID=$!

# Wait briefly for socket to be ready
sleep 0.2

# Trap signals to forward to both processes
trap "kill $NETHELPER_PID 2>/dev/null; wait $NETHELPER_PID 2>/dev/null" TERM INT

# Drop privileges and run the agent
exec su-exec prysm /app/prysm-agent "$@"
