import { createPrivateKey, sign } from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { GateError, assert } from './errors.js';
import { awsKmsSigner, createCredentialProvider } from './aws-kms.js';

const failed = (message) => new GateError(502, 'SIGNER_FAILED', message);

export function localSigner(privateKey) {
  const key = createPrivateKey(privateKey);
  assert(key.asymmetricKeyType === 'rsa', 'GitHub App key must be RSA');
  return { kind: 'local', sign: async (data) => sign('RSA-SHA256', data, key) };
}

// Runs an external program (for example a KMS CLI) that reads the JWT signing
// input on stdin and writes the raw RSASSA-PKCS1-v1_5 SHA-256 signature to stdout.
export function commandSigner(argv, { timeoutMs = 10_000 } = {}) {
  assert(Array.isArray(argv) && argv.length > 0 && argv.every((part) => typeof part === 'string' && part.length > 0),
    'AGENTGATE_SIGN_COMMAND must be a nonempty JSON array of strings');
  return {
    kind: 'command',
    sign: (data) => new Promise((resolve, reject) => {
      const child = spawn(argv[0], argv.slice(1), { stdio: ['pipe', 'pipe', 'ignore'], timeout: timeoutMs, killSignal: 'SIGKILL' });
      const chunks = [];
      child.stdout.on('data', (chunk) => chunks.push(chunk));
      child.stdin.on('error', () => { /* Reported through close or error. */ });
      child.on('error', () => reject(failed('App JWT signer could not run')));
      child.on('close', (code, signal) => {
        const signature = Buffer.concat(chunks);
        // RSA-2048 and larger produce at least 256 bytes.
        if (code !== 0 || signal || signature.length < 256) return reject(failed(`App JWT signer failed (${signal ?? code})`));
        resolve(signature);
      });
      child.stdin.end(data);
    })
  };
}

// Precedence: an explicit signing command, then native AWS KMS, then a local key file. KMS and a
// key file together is refused rather than silently picking one, so a deployment cannot believe
// the PEM is unused while it is still readable.
export function signerFromEnv(env = process.env, { fetchImpl = fetch } = {}) {
  if (env.AGENTGATE_SIGN_COMMAND) {
    let argv;
    try { argv = JSON.parse(env.AGENTGATE_SIGN_COMMAND); } catch { throw new Error('AGENTGATE_SIGN_COMMAND must be a JSON array'); }
    return commandSigner(argv);
  }
  if (env.AGENTGATE_KMS_KEY_ID) {
    if (env.GITHUB_PRIVATE_KEY_PATH) throw new Error('Set AGENTGATE_KMS_KEY_ID or GITHUB_PRIVATE_KEY_PATH, not both');
    return awsKmsSigner({ keyId: env.AGENTGATE_KMS_KEY_ID, region: env.AWS_REGION || env.AWS_DEFAULT_REGION, endpoint: env.AGENTGATE_KMS_ENDPOINT, credentials: createCredentialProvider({ env, fetchImpl }), fetchImpl });
  }
  if (!env.GITHUB_PRIVATE_KEY_PATH) throw new Error('Set AGENTGATE_SIGN_COMMAND, AGENTGATE_KMS_KEY_ID, or GITHUB_PRIVATE_KEY_PATH');
  return localSigner(readFileSync(env.GITHUB_PRIVATE_KEY_PATH));
}
