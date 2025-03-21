#!/bin/bash
set -e

# Create user `test_user_group` with the same password
adduser -D -H -s /bin/bash test_user_group && echo "test_user_group:pass" | chpasswd

# Set up SSH folder (for pubkey-based auth)
mkdir -p /home/test_user_group/.ssh
chmod 700 /home/test_user_group/.ssh
chown -R test_user_group:test_user_group /home/test_user_group

# If you want to share authorized_keys from volume:
cp /config/.ssh/authorized_keys /home/test_user_group/.ssh/authorized_keys 2>/dev/null || true
chown test_user_group:test_user_group /home/test_user_group/.ssh/authorized_keys
chmod 600 /home/test_user_group/.ssh/authorized_keys

