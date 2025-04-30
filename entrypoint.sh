#!/bin/sh
set -e

PLUGIN=${PLUGIN:-fixed}
export SSHPIPERD_SERVER_KEY_GENERATE_MODE="${SSHPIPERD_SERVER_KEY_GENERATE_MODE:-notexist}"

if [ "$PLUGIN" = "fixed" ]; then
  exec /sshpiperd/sshpiperd /sshpiperd/plugins/fixed --target=127.0.0.1:22
else
  exec /sshpiperd/sshpiperd "${@:-/sshpiperd/plugins/$PLUGIN}"
fi
