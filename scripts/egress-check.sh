#!/bin/sh
# Run inside the workspace container on each deployment host.
set -u
status=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; status=1; }

# curl exit codes that mean an outbound connection attempt was made and
# legitimately failed to reach anything: 6 could not resolve host, 7 failed
# to connect, 28 operation timeout, 35 SSL connect error, 52 server returned
# nothing, 56 failure receiving network data (verified against `curl --manual`
# EXIT CODES in this image's curl 7.88.1). Any other non-zero exit (1
# unsupported protocol, 2 failed init, 3 malformed URL, 4 feature not built,
# etc.) means the probe itself could not run, not that egress was blocked.
is_blocked_exit() {
  case "$1" in
    6 | 7 | 28 | 35 | 52 | 56) return 0 ;;
    *) return 1 ;;
  esac
}

blocked() { # $1 label, rest: curl args. Passes only on a network-level refusal/absence.
  label=$1; shift
  curl --noproxy '*' --connect-timeout 3 --max-time 5 --silent --output /dev/null "$@"
  code=$?
  if [ "$code" -eq 0 ]; then fail "$label"
  elif is_blocked_exit "$code"; then pass "$label"
  else fail "$label: probe could not run (curl exit $code)"
  fi
}

blocked 'direct HTTPS to github.com' https://github.com
blocked 'direct HTTPS to api.github.com' https://api.github.com
blocked 'direct IPv4 to 140.82.112.3:443' https://140.82.112.3 -k
blocked 'IPv6 egress' -6 https://github.com
blocked 'cloud metadata 169.254.169.254' http://169.254.169.254/
blocked 'cloud metadata fd00:ec2::254' 'http://[fd00:ec2::254]/'

# The gateway probes use the telnet:// scheme, which requires curl to have
# been built with telnet support. Preflight that explicitly instead of
# letting it surface as a generic non-zero curl exit code.
curl_protocols=$(curl --version 2>/dev/null | awk -F': ' '/^Protocols:/ {print $2}')
case " $curl_protocols " in
  *' telnet '*) telnet_supported=1 ;;
  *) telnet_supported=0 ;;
esac

if ! command -v ip >/dev/null 2>&1; then
  fail 'gateway probe: ip command not found'
else
  route_output=$(ip route 2>/dev/null)
  route_status=$?
  if [ "$route_status" -ne 0 ]; then
    fail "gateway probe: ip route failed (exit $route_status)"
  else
    gateway=$(printf '%s\n' "$route_output" | awk '/^default/ {print $3; exit}')
    if [ -n "$gateway" ]; then
      if [ "$telnet_supported" -eq 1 ]; then
        blocked "host gateway $gateway:22" "telnet://$gateway:22"
      else
        fail "host gateway $gateway:22: curl built without telnet support"
      fi
      blocked "host gateway $gateway:2375 (Docker API)" "http://$gateway:2375/version"
    else
      pass 'no default route'
    fi
  fi
fi

blocked 'plain HTTP egress' http://example.com

# External DNS must not resolve: the workspace uses `dns: ["127.0.0.1"]`, so only
# Docker service names answer and the proxy resolves allowlisted names itself.
# getent exit 2 means "not found"; exit 0 is an open DNS channel; anything else
# means the probe could not run.
if ! command -v getent >/dev/null 2>&1; then
  fail 'DNS probe could not run (getent not found)'
else
  getent hosts example.com >/dev/null 2>&1
  dns_status=$?
  case "$dns_status" in
    0) fail 'external DNS resolution blocked (example.com resolves; DNS exfiltration channel open)' ;;
    2) pass 'external DNS resolution blocked' ;;
    *) fail "DNS probe could not run (getent exit $dns_status)" ;;
  esac
fi

# Egress proxy. Positive: an allowlisted registry is reachable through it.
# Negative: the proxy itself must refuse (CONNECT status 403) non-allowlisted
# hosts, GitHub (broker only) and IP literals; a proxy that is merely down or a
# probe that cannot run is a FAIL, never a pass.
proxy_url="${HTTPS_PROXY:-${https_proxy:-}}"
proxy_refuses() { # $1 label, $2 URL. Passes only when the proxy answers CONNECT with 403.
  connect_code=$(curl --silent --output /dev/null --connect-timeout 5 --max-time 10 --proxy "$proxy_url" --write-out '%{http_connect}' "$2")
  curl_status=$?
  if [ "$curl_status" -eq 0 ]; then fail "$1 (reachable through proxy)"
  elif [ "$connect_code" = 403 ]; then pass "$1"
  else fail "$1: proxy did not refuse (curl exit $curl_status, CONNECT status ${connect_code:-none})"
  fi
}
if [ -z "$proxy_url" ]; then
  fail 'egress proxy configured (HTTPS_PROXY unset)'
else
  if curl --silent --output /dev/null --connect-timeout 5 --max-time 10 --proxy "$proxy_url" https://registry.npmjs.org/; then pass 'allowlisted egress via proxy'; else fail 'allowlisted egress via proxy'; fi
  proxy_refuses 'non-allowlisted egress via proxy refused' https://example.com/
  proxy_refuses 'GitHub via proxy refused (broker only)' https://github.com/
  proxy_refuses 'IP literal via proxy refused' https://140.82.112.3/
fi

if env | grep -Eq '^(GITHUB_TOKEN|GH_TOKEN|GITHUB_PRIVATE_KEY_PATH|GITHUB_APP_ID|AGENTGATE_SIGN_COMMAND|AGENTGATE_KMS_KEY_ID)='; then fail 'no GitHub credentials in environment'; else pass 'no GitHub credentials in environment'; fi

if [ -r /proc/1/environ ]; then
  environ_content=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null)
  read_status=$?
  if [ "$read_status" -ne 0 ]; then
    fail 'cannot inspect PID 1 environment'
  elif printf '%s\n' "$environ_content" | grep -Eq '^(GITHUB_TOKEN|GH_TOKEN|GITHUB_PRIVATE_KEY_PATH)='; then
    fail 'no credentials in PID 1 environment'
  else
    pass 'no credentials in PID 1 environment'
  fi
else
  fail 'cannot inspect PID 1 environment'
fi

if [ -e /run/secrets/github_app_key ] || [ -e /var/lib/agentgate ]; then fail 'broker key and state not mounted'; else pass 'broker key and state not mounted'; fi

# Content-based scan for private-key material anywhere on the filesystem
# (not just files named after AgentBox), since a key could be mounted or
# copied under any name. Skip pseudo filesystems (/proc, /sys, /dev), public
# CA bundle directories (which legitimately contain certificates, never
# private keys), and the workspace's own trusted CA file, if any. Limit to
# files under 64 KiB so the scan stays fast and never reads large binaries.
# Two exact-file exclusions, each individually verified by inspection (never
# a whole-directory prune, so anything else under the same tree is still
# scanned): this script itself necessarily contains the search string as a
# literal, and the image's bundled npm ships two documentation files showing
# an all-X placeholder in that exact format as an example of the `key`
# config option, not real key material — confirmed by inspection:
# `key="-----BEGIN PRIVATE KEY-----\nXXXX\nXXXX\n-----END PRIVATE KEY-----"`
# in both /usr/local/lib/node_modules/npm/man/man7/config.7 and
# /usr/local/lib/node_modules/npm/docs/content/using-npm/config.md.
ca_file="${AGENTGATE_CA_FILE:-/nonexistent-agentgate-ca-placeholder}"
key_hits=$(find / \( \
      -path /proc -o -path /sys -o -path /dev \
      -o -path /etc/ssl/certs -o -path /usr/share/ca-certificates -o -path /usr/lib/ssl \
      -o -path "$ca_file" \
    \) -prune -o -type f -size -64k \
      ! -path /usr/local/bin/agentgate-egress-check \
      ! -path /usr/local/lib/node_modules/npm/man/man7/config.7 \
      ! -path /usr/local/lib/node_modules/npm/docs/content/using-npm/config.md \
      -print 2>/dev/null \
  | xargs -r grep -l -- 'PRIVATE KEY-----' 2>/dev/null)
if [ -n "$key_hits" ]; then
  fail 'no private key material on filesystem'
  printf '%s\n' "$key_hits" | while IFS= read -r hit; do echo "  found: $hit"; done
else
  pass 'no private key material on filesystem'
fi

if [ -S /var/run/docker.sock ]; then fail 'Docker socket absent'; else pass 'Docker socket absent'; fi
if grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/self/status; then pass 'no effective capabilities'; else fail 'no effective capabilities'; fi
if curl --connect-timeout 3 --max-time 5 --silent --fail "${AGENTGATE_URL:-http://agentd:7432}/healthz" ${AGENTGATE_CA_FILE:+--cacert "$AGENTGATE_CA_FILE"} >/dev/null; then pass 'broker reachable'; else fail 'broker reachable'; fi

if [ "$status" -ne 0 ]; then exit 1; fi
exit 0
