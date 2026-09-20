#!/bin/sh
set -eu
node /opt/agentgate/src/workspace-setup.js
# Same environment for PID 1 and for every shell opened later with `docker compose exec` or an
# IDE attach: /etc/profile.d covers login shells; ~/.bashrc (persistent home volume) covers
# interactive non-login ones. Non-interactive exec commands need `bash -lc`.
. /etc/profile.d/agentgate.sh
if [ -w "$HOME" ] && ! grep -qs 'profile.d/agentgate.sh' "$HOME/.bashrc"; then
  printf '\n# AgentBox workspace environment (managed by the entrypoint)\n[ -r /etc/profile.d/agentgate.sh ] && . /etc/profile.d/agentgate.sh\n' >> "$HOME/.bashrc"
fi
exec "$@"
