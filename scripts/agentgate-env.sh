# Sourced by login shells (/etc/profile.d) and, via the workspace entrypoint, by ~/.bashrc, so that
# shells started with `docker compose exec` or by an IDE's Dev Containers attach get the same
# environment the entrypoint gives PID 1. Model SDKs send ANTHROPIC_AUTH_TOKEN as a Bearer token to
# ANTHROPIC_BASE_URL (the model gateway), which strips it and injects the real provider key. It is
# the model-gateway client token, never a provider key.
if [ -n "${AGENTGATE_MODEL_GATEWAY_TOKEN_FILE:-}" ] && [ -r "$AGENTGATE_MODEL_GATEWAY_TOKEN_FILE" ]; then
  ANTHROPIC_AUTH_TOKEN="$(cat "$AGENTGATE_MODEL_GATEWAY_TOKEN_FILE")"
  export ANTHROPIC_AUTH_TOKEN
fi
# Claude Code sends extra request headers from ANTHROPIC_CUSTOM_HEADERS ("Name: value" lines). With
# the runtime assertion attached, a model gateway configured with the issuer keys attributes each
# request and its budget to this runtime instead of only to the workspace's address.
if [ -n "${AGENTGATE_RUNTIME_ASSERTION_FILE:-}" ] && [ -s "$AGENTGATE_RUNTIME_ASSERTION_FILE" ]; then
  ANTHROPIC_CUSTOM_HEADERS="x-agentgate-runtime: $(cat "$AGENTGATE_RUNTIME_ASSERTION_FILE")"
  export ANTHROPIC_CUSTOM_HEADERS
fi
# The egress proxy attributes tunnels to a runtime when the proxy URL carries the assertion as
# credentials (user "runtime"); Git, curl, npm, pip, and apt all send them as Proxy-Authorization.
# Only rewritten when the URL has no credentials yet, so a rerun of this file is harmless.
if [ -n "${AGENTGATE_RUNTIME_ASSERTION_FILE:-}" ] && [ -s "$AGENTGATE_RUNTIME_ASSERTION_FILE" ]; then
  agentbox_assertion="$(cat "$AGENTGATE_RUNTIME_ASSERTION_FILE")"
  for agentbox_var in HTTPS_PROXY HTTP_PROXY https_proxy http_proxy; do
    eval "agentbox_url=\${$agentbox_var:-}"
    case "$agentbox_url" in
      *@*|'') ;;
      http://*) eval "$agentbox_var=\"http://runtime:\$agentbox_assertion@\${agentbox_url#http://}\""; export "$agentbox_var" ;;
    esac
  done
  unset agentbox_assertion agentbox_var agentbox_url
fi
# Behind a proxy that inspects TLS, tools must also trust the company root CA. workspace-setup.js
# builds the bundle (public roots plus that CA); Node adds the CA file to its built-in roots. Git is
# configured by workspace-setup.js, and the broker keeps its own CA either way.
if [ -n "${AGENTGATE_CORPORATE_CA_FILE:-}" ] && [ -r "$HOME/.config/agentgate/ca-bundle.crt" ]; then
  SSL_CERT_FILE="$HOME/.config/agentgate/ca-bundle.crt"
  CURL_CA_BUNDLE="$SSL_CERT_FILE"
  REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
  PIP_CERT="$SSL_CERT_FILE"
  NODE_EXTRA_CA_CERTS="$AGENTGATE_CORPORATE_CA_FILE"
  export SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE PIP_CERT NODE_EXTRA_CA_CERTS
fi
