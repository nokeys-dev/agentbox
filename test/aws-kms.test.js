import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign, verify } from 'node:crypto';
import { awsKmsSigner, createCredentialProvider, signV4 } from '../src/aws-kms.js';
import { signerFromEnv } from '../src/signer.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const now = () => Date.parse('2026-09-18T12:00:00Z');

test('signV4 matches the AWS worked example structure and includes the session token when present', () => {
  const headers = signV4({ url: 'https://kms.us-east-1.amazonaws.com/', headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Sign' }, body: '{}',
    region: 'us-east-1', service: 'kms', credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', sessionToken: 'session' }, now });
  assert.equal(headers['x-amz-date'], '20260918T120000Z');
  assert.equal(headers.host, 'kms.us-east-1.amazonaws.com');
  assert.equal(headers['x-amz-security-token'], 'session');
  assert.match(headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20260918\/us-east-1\/kms\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/);
  // Independent recomputation of the signature from the documented algorithm.
  const scope = '20260918/us-east-1/kms/aws4_request';
  const canonical = ['POST', '/', '', 'content-type:application/x-amz-json-1.1\nhost:kms.us-east-1.amazonaws.com\nx-amz-date:20260918T120000Z\nx-amz-security-token:session\nx-amz-target:TrentService.Sign\n',
    'content-type;host;x-amz-date;x-amz-security-token;x-amz-target', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', '20260918T120000Z', scope, createHash('sha256').update(canonical).digest('hex')].join('\n');
  const key = ['20260918', 'us-east-1', 'kms', 'aws4_request'].reduce((k, part) => createHmac('sha256', k).update(part).digest(), 'AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');
  assert.ok(headers.authorization.endsWith(createHmac('sha256', key).update(stringToSign).digest('hex')));
});

test('KMS signer sends a SigV4-signed Sign request and returns a verifiable RS256 signature', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    const request = JSON.parse(options.body);
    assert.equal(request.KeyId, 'alias/agentgate-app');
    assert.equal(request.SigningAlgorithm, 'RSASSA_PKCS1_V1_5_SHA_256');
    assert.equal(request.MessageType, 'RAW');
    assert.match(options.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKID\/\d{8}\/eu-west-1\/kms\/aws4_request/);
    assert.equal(options.headers['x-amz-target'], 'TrentService.Sign');
    assert.equal(options.redirect, 'error');
    return Response.json({ Signature: sign('RSA-SHA256', Buffer.from(request.Message, 'base64'), privateKey).toString('base64') });
  };
  const signer = awsKmsSigner({ keyId: 'alias/agentgate-app', region: 'eu-west-1', credentials: async () => ({ accessKeyId: 'AKID', secretAccessKey: 'secret' }), fetchImpl });
  assert.equal(signer.kind, 'aws-kms');
  const signature = await signer.sign(Buffer.from('header.payload'));
  assert.ok(verify('RSA-SHA256', Buffer.from('header.payload'), publicKey, signature));
  assert.equal(calls[0].url, 'https://kms.eu-west-1.amazonaws.com/');
  const arn = awsKmsSigner({ keyId: 'arn:aws:kms:us-west-2:123456789012:key/abcd', credentials: async () => ({ accessKeyId: 'a', secretAccessKey: 'b' }), fetchImpl: async (url) => { calls.push({ url }); return Response.json({ Signature: 'AA==' }); } });
  await assert.rejects(arn.sign(Buffer.from('x')), { code: 'SIGNER_FAILED' });
  assert.equal(calls.at(-1).url, 'https://kms.us-west-2.amazonaws.com/', 'region inferred from the key ARN');
  await assert.rejects(awsKmsSigner({ keyId: 'alias/x', region: 'eu-west-1', credentials: async () => ({ accessKeyId: 'a', secretAccessKey: 'b' }), fetchImpl: async () => new Response('AccessDenied', { status: 400 }) }).sign(Buffer.from('x')), /KMS Sign 400/);
  await assert.rejects(awsKmsSigner({ keyId: 'alias/x', region: 'eu-west-1', credentials: async () => ({ accessKeyId: 'a', secretAccessKey: 'b' }), fetchImpl: async () => { throw new Error('ECONNRESET secret-host'); } }).sign(Buffer.from('x')), { code: 'SIGNER_FAILED', message: /KMS request failed$/ });
  assert.throws(() => awsKmsSigner({ keyId: 'alias/x', credentials: async () => ({}) }), /AWS_REGION/);
  assert.throws(() => awsKmsSigner({ keyId: 'alias/x', region: 'eu-west-1', endpoint: 'http://kms.local/', credentials: async () => ({}) }), /https/);
});

test('credential provider resolves web identity through STS, caches until expiry, and falls back in order', async () => {
  let clock = now();
  let stsCalls = 0;
  const fetchImpl = async (url, options) => {
    stsCalls++;
    assert.equal(url, 'https://sts.eu-west-1.amazonaws.com/');
    const form = new URLSearchParams(options.body);
    assert.equal(form.get('Action'), 'AssumeRoleWithWebIdentity');
    assert.equal(form.get('RoleArn'), 'arn:aws:iam::123456789012:role/agentgate');
    assert.equal(form.get('WebIdentityToken'), 'oidc-token');
    return new Response(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA${stsCalls}</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>${new Date(clock + 3600_000).toISOString()}</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, { status: 200 });
  };
  const provider = createCredentialProvider({ env: { AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/agentgate', AWS_WEB_IDENTITY_TOKEN_FILE: '/token', AWS_REGION: 'eu-west-1' }, fetchImpl, now: () => clock, readFile: () => 'oidc-token\n' });
  assert.equal((await provider()).accessKeyId, 'ASIA1');
  assert.equal((await provider()).accessKeyId, 'ASIA1', 'cached');
  clock += 3600_000;
  assert.equal((await provider()).accessKeyId, 'ASIA2', 'refreshed after expiry');

  const container = createCredentialProvider({ env: { AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.23/v1/credentials', AWS_CONTAINER_AUTHORIZATION_TOKEN: 'pod-token' },
    fetchImpl: async (url, options) => { assert.equal(options.headers.authorization, 'pod-token'); return Response.json({ AccessKeyId: 'ASIAC', SecretAccessKey: 's', Token: 't', Expiration: new Date(clock + 600_000).toISOString() }); } });
  assert.equal((await container()).sessionToken, 't');
  await assert.rejects(createCredentialProvider({ env: { AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://evil.example/creds' }, fetchImpl: async () => Response.json({}) })(), /not allowed/);
  const fixed = createCredentialProvider({ env: { AWS_ACCESS_KEY_ID: 'AKIA', AWS_SECRET_ACCESS_KEY: 'k' } });
  assert.deepEqual(await fixed(), { accessKeyId: 'AKIA', secretAccessKey: 'k', sessionToken: undefined });
  await assert.rejects(createCredentialProvider({ env: {} })(), /No AWS credentials/);
  await assert.rejects(createCredentialProvider({ env: { AWS_ROLE_ARN: 'r', AWS_WEB_IDENTITY_TOKEN_FILE: '/t', AWS_REGION: 'eu-west-1' }, fetchImpl: async () => new Response('<Error>secret</Error>', { status: 403 }), readFile: () => 'x' })(), { code: 'SIGNER_FAILED', message: /AWS STS 403$/ });
});

test('signerFromEnv picks KMS from AGENTGATE_KMS_KEY_ID and refuses a key file alongside it', () => {
  assert.equal(signerFromEnv({ AGENTGATE_KMS_KEY_ID: 'alias/x', AWS_REGION: 'eu-west-1', AWS_ACCESS_KEY_ID: 'a', AWS_SECRET_ACCESS_KEY: 'b' }).kind, 'aws-kms');
  assert.throws(() => signerFromEnv({ AGENTGATE_KMS_KEY_ID: 'alias/x', AWS_REGION: 'eu-west-1', GITHUB_PRIVATE_KEY_PATH: '/k.pem' }), /not both/);
  assert.throws(() => signerFromEnv({}), /AGENTGATE_KMS_KEY_ID/);
});
