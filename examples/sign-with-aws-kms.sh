#!/bin/sh
# Signs the GitHub App JWT input from stdin with an asymmetric RSA_2048 KMS key.
# Import the GitHub App private key into KMS (or generate it there and register
# the public key with GitHub), then grant the broker role only kms:Sign on it.
# Usage: AGENTGATE_SIGN_COMMAND='["/etc/agentgate/sign-with-aws-kms.sh"]'
set -eu
: "${AGENTGATE_KMS_KEY_ID:?Set AGENTGATE_KMS_KEY_ID}"
input=$(mktemp)
trap 'rm -f "$input"' EXIT
cat > "$input"
aws kms sign \
  --key-id "$AGENTGATE_KMS_KEY_ID" \
  --message "fileb://$input" \
  --message-type RAW \
  --signing-algorithm RSASSA_PKCS1_V1_5_SHA_256 \
  --output text --query Signature | base64 -d
