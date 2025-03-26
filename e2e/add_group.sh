#!/bin/sh
set -e

# Add a group called "testgroup" with GID 9999 (optional)
addgroup -g 9999 testgroup || echo "Group already exists or cannot be created"
adduser testuser -D -G testgroup
