// Native AWS KMS signing for GitHub App JWTs: SigV4-signed KMS Sign requests with no SDK or CLI
// in the broker image. Credentials come from, in order, the container credential endpoint
// (ECS/EKS Pod Identity: AWS_CONTAINER_CREDENTIALS_FULL_URI or _RELATIVE_URI), web identity
// (IRSA: AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE via STS AssumeRoleWithWebIdentity), or static
// environment keys. Credentials are cached until shortly before expiry. Nothing here logs a
// credential, a request body, or a response body; failures surface as SIGNER_FAILED.
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { GateError } from './errors.js';

const failed = (message) => new GateError(502, 'SIGNER_FAILED', message);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => createHmac('sha256', key).update(value).digest();

// AWS Signature Version 4 for a single POST with a fixed set of headers.
export function signV4({ method = 'POST', url, headers, body, region, service, credentials, now = Date.now }) {
  const target = new URL(url);
  const date = new Date(now()).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const day = date.slice(0, 8);
  const signed = { ...headers, host: target.host, 'x-amz-date': date, ...(credentials.sessionToken ? { 'x-amz-security-token': credentials.sessionToken } : {}) };
  const names = Object.keys(signed).map((name) => name.toLowerCase()).sort();
  const canonicalHeaders = names.map((name) => `${name}:${String(signed[Object.keys(signed).find((key) => key.toLowerCase() === name)]).trim()}\n`).join('');
  const signedHeaders = names.join(';');
  const payloadHash = sha256(body);
  const canonicalRequest = [method, target.pathname || '/', target.search.slice(1), canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${day}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', date, scope, sha256(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${credentials.secretAccessKey}`, day), region), service), 'aws4_request');
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  return { ...signed, authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}

const xmlField = (text, name) => new RegExp(`<${name}>([^<]*)</${name}>`).exec(text)?.[1];

export function createCredentialProvider({ env = process.env, fetchImpl = fetch, now = Date.now, readFile = (path) => readFileSync(path, 'utf8') } = {}) {
  let cached;
  const fresh = (value) => value && (!value.expiresAt || value.expiresAt > now() + 60_000);
  const fetchJson = async (url, options) => {
    const response = await fetchImpl(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (response.status !== 200) { await response.body?.cancel(); throw failed(`AWS credential endpoint ${response.status}`); }
    return response.json();
  };
  const resolve = async () => {
    if (env.AWS_CONTAINER_CREDENTIALS_FULL_URI || env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
      const url = env.AWS_CONTAINER_CREDENTIALS_FULL_URI || `http://169.254.170.2${env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}`;
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol) || (parsed.protocol === 'http:' && !['169.254.170.2', '169.254.170.23', 'localhost', '127.0.0.1'].includes(parsed.hostname) && !parsed.hostname.startsWith('[fd00:ec2::'))) throw failed('AWS container credential URI is not allowed');
      const headers = {};
      if (env.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) headers.authorization = readFile(env.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE).trim();
      else if (env.AWS_CONTAINER_AUTHORIZATION_TOKEN) headers.authorization = env.AWS_CONTAINER_AUTHORIZATION_TOKEN;
      const body = await fetchJson(url, { headers });
      if (typeof body?.AccessKeyId !== 'string' || typeof body?.SecretAccessKey !== 'string') throw failed('AWS container credentials malformed');
      return { accessKeyId: body.AccessKeyId, secretAccessKey: body.SecretAccessKey, sessionToken: body.Token, expiresAt: body.Expiration ? Date.parse(body.Expiration) : undefined };
    }
    if (env.AWS_ROLE_ARN && env.AWS_WEB_IDENTITY_TOKEN_FILE) {
      const token = readFile(env.AWS_WEB_IDENTITY_TOKEN_FILE).trim();
      const query = new URLSearchParams({ Action: 'AssumeRoleWithWebIdentity', Version: '2011-06-15', RoleArn: env.AWS_ROLE_ARN,
        RoleSessionName: (env.AWS_ROLE_SESSION_NAME || 'agentgate').replace(/[^\w+=,.@-]/g, '-').slice(0, 64), WebIdentityToken: token, DurationSeconds: '3600' });
      const region = env.AWS_REGION || env.AWS_DEFAULT_REGION;
      const url = env.AWS_STS_ENDPOINT || (region ? `https://sts.${region}.amazonaws.com/` : 'https://sts.amazonaws.com/');
      const response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'text/xml' }, body: query.toString(), redirect: 'error', signal: AbortSignal.timeout(10_000) });
      const text = await response.text();
      if (response.status !== 200) throw failed(`AWS STS ${response.status}`);
      const accessKeyId = xmlField(text, 'AccessKeyId');
      const secretAccessKey = xmlField(text, 'SecretAccessKey');
      const sessionToken = xmlField(text, 'SessionToken');
      const expiration = xmlField(text, 'Expiration');
      if (!accessKeyId || !secretAccessKey || !sessionToken) throw failed('AWS STS response malformed');
      return { accessKeyId, secretAccessKey, sessionToken, expiresAt: expiration ? Date.parse(expiration) : now() + 3600_000 };
    }
    if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) {
      return { accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY, sessionToken: env.AWS_SESSION_TOKEN };
    }
    throw failed('No AWS credentials: set AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_ROLE_ARN with AWS_WEB_IDENTITY_TOKEN_FILE, or AWS_ACCESS_KEY_ID');
  };
  return async () => {
    if (fresh(cached)) return cached;
    cached = await resolve();
    return cached;
  };
}

export function awsKmsSigner({ keyId, region, credentials, fetchImpl = fetch, now = Date.now, endpoint }) {
  if (typeof keyId !== 'string' || !/^[A-Za-z0-9:/_.-]{1,2048}$/.test(keyId)) throw new Error('AGENTGATE_KMS_KEY_ID must be a KMS key ID, ARN, or alias');
  const inferred = region || /^arn:aws[a-z-]*:kms:([a-z0-9-]+):/.exec(keyId)?.[1];
  if (typeof inferred !== 'string' || !/^[a-z0-9-]{1,32}$/.test(inferred)) throw new Error('Set AWS_REGION (or use a KMS key ARN) for KMS signing');
  const url = endpoint || `https://kms.${inferred}.amazonaws.com/`;
  if (!/^https:\/\//.test(url)) throw new Error('KMS endpoint must be https');
  return {
    kind: 'aws-kms',
    sign: async (data) => {
      const body = JSON.stringify({ KeyId: keyId, Message: Buffer.from(data).toString('base64'), MessageType: 'RAW', SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256' });
      const headers = signV4({ url, headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Sign' }, body, region: inferred, service: 'kms', credentials: await credentials(), now });
      let response;
      try {
        response = await fetchImpl(url, { method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(10_000) });
      } catch { throw failed('KMS request failed'); }
      if (response.status !== 200) { await response.body?.cancel(); throw failed(`KMS Sign ${response.status}`); }
      let parsed;
      try { parsed = await response.json(); } catch { throw failed('KMS response malformed'); }
      const signature = typeof parsed?.Signature === 'string' ? Buffer.from(parsed.Signature, 'base64') : Buffer.alloc(0);
      if (signature.length < 256) throw failed('KMS returned no usable signature');
      return signature;
    }
  };
}
