#!/bin/sh
# Creates a private CA and a broker certificate for 127.0.0.1, localhost, and agentd.
# Development and test use only; production certificates come from your PKI.
set -eu
out=${1:?Usage: make-dev-cert.sh OUTPUT_DIR}
umask 077
mkdir -p "$out"
chmod 700 "$out"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=AgentBox Dev CA' \
  -keyout "$out/ca.key" -out "$out/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj '/CN=agentd' \
  -keyout "$out/broker.key" -out "$out/broker.csr" 2>/dev/null
printf 'subjectAltName=DNS:agentd,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$out/ext.cnf"
openssl x509 -req -in "$out/broker.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" -CAcreateserial \
  -days 30 -extfile "$out/ext.cnf" -out "$out/broker.crt" 2>/dev/null
rm -f "$out/broker.csr" "$out/ext.cnf" "$out/ca.srl"
chmod 644 "$out/ca.crt"
