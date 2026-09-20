#!/bin/sh
# Generates everything one developer's machine can generate for the core Compose stack, and
# writes the matching entries into .env: the workspace client token, the model-gateway client
# token, and a development CA plus broker certificate. Safe to rerun: existing secrets are kept,
# existing .env lines for these keys are replaced in place, other lines are untouched.
#
# Usage: sh scripts/bootstrap-dev.sh [SECRETS_DIR]   (default: $HOME/.agentgate)
#
# What it does not do, because only your platform team can: the GitHub App ID and signing key
# (or KMS settings), the model provider key, config.local.json contents, and your runtime
# assertion. It prints exactly those at the end.
set -eu
dir=${1:-"$HOME/.agentgate"}
here=$(cd "$(dirname "$0")" && pwd)
env_file=.env
umask 077
mkdir -p "$dir"
chmod 700 "$dir"

generate_token() {
  if [ ! -s "$1" ]; then
    openssl rand -hex 32 | tr -d '\n' > "$1"
    echo "created $1"
  else
    echo "kept    $1"
  fi
  chmod 600 "$1"
}

set_env() {
  key=$1; value=$2
  if [ -f "$env_file" ] && grep -q "^$key=" "$env_file"; then
    # Replace in place without sed's regex surprises in the value: rebuild the file.
    tmp="$env_file.$$.tmp"
    awk -v k="$key" -v v="$value" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$env_file" > "$tmp"
    mv "$tmp" "$env_file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$env_file"
  fi
}

generate_token "$dir/client-token"
generate_token "$dir/model-gateway-token"
# The development certificates last 30 days. Renew them when either has under a week left, so a
# rerun is the fix for an expired certificate rather than a silent "kept".
renew_before=604800
if [ ! -s "$dir/tls/broker.crt" ] || [ ! -s "$dir/tls/ca.crt" ]; then
  sh "$here/make-dev-cert.sh" "$dir/tls"
  echo "created $dir/tls (development CA and broker certificate, 30 days)"
elif ! openssl x509 -checkend "$renew_before" -noout -in "$dir/tls/broker.crt" >/dev/null 2>&1 ||
     ! openssl x509 -checkend "$renew_before" -noout -in "$dir/tls/ca.crt" >/dev/null 2>&1; then
  sh "$here/make-dev-cert.sh" "$dir/tls"
  echo "renewed $dir/tls (expired or under 7 days left); recreate the stack to load it: up -d --force-recreate"
else
  echo "kept    $dir/tls"
fi

[ -f "$env_file" ] || { : > "$env_file"; chmod 600 "$env_file"; echo "created $env_file"; }
set_env AGENTGATE_CLIENT_TOKEN_PATH "$dir/client-token"
set_env AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH "$dir/model-gateway-token"
set_env AGENTGATE_TLS_CERT_PATH "$dir/tls/broker.crt"
set_env AGENTGATE_TLS_KEY_PATH "$dir/tls/broker.key"
set_env AGENTGATE_CA_PATH "$dir/tls/ca.crt"
echo "updated $env_file"

if [ ! -f config.local.json ] && [ -f "$here/../examples/config.json" ]; then
  cp "$here/../examples/config.json" config.local.json
  chmod 600 config.local.json
  echo "created config.local.json from examples/config.json (edit the repositories and rules)"
fi

missing=""
for key in GITHUB_APP_ID GITHUB_PRIVATE_KEY_PATH ANTHROPIC_API_KEY_PATH AGENTGATE_GIT_NAME AGENTGATE_GIT_EMAIL; do
  grep -q "^$key=" "$env_file" || missing="$missing $key"
done
echo
echo "Still needed in $env_file before bringing the stack up:"
for key in $missing; do
  case $key in
    GITHUB_APP_ID)          echo "  $key                 the GitHub App ID from your platform team";;
    GITHUB_PRIVATE_KEY_PATH) echo "  $key       the App key file, or /dev/null with the compose.kms.yaml override";;
    ANTHROPIC_API_KEY_PATH) echo "  $key        a file holding the model provider key (the gateway injects it)";;
    AGENTGATE_GIT_NAME)     echo "  $key            your commit name";;
    AGENTGATE_GIT_EMAIL)    echo "  $key           your commit email";;
  esac
done
[ -n "$missing" ] || echo "  nothing: every core setting is present"
echo
# Under "agentbox init" the command prints its own next step.
[ -n "${AGENTBOX_CLI:-}" ] || echo "Then: docker compose up -d --build && docker compose exec workspace agentgate fingerprint"
echo "Send the fingerprint to whoever issues your runtime assertion (docs/onboarding.md), save the"
echo "file they return, and set AGENTGATE_RUNTIME_ASSERTION_PATH in $env_file."
