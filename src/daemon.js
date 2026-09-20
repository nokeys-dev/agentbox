import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadConfig, validateConfig } from './config.js';
import { loadClientToken } from './client-auth.js';
import { GitHub } from './github.js';
import { GitLab } from './gitlab.js';
import { signerFromEnv } from './signer.js';
import { startGate } from './server.js';
import { Mirror, mirrorDirectory } from './mirror.js';
import { isLfsHost } from './lfs.js';
import { verifyProtectedBranches } from './rulesets.js';
import { reloadConfig } from './reload.js';
import { createLogger } from './log.js';
import { createNotifier } from './notify.js';
import { readAdminSecret } from './admin-auth.js';
import { edition, requireEdition } from './extensions.js';
import { assertProvider } from './providers/index.js';
import { loadRevocationsFile } from './revocations.js';

process.umask(0o077);

// warn/error go to stderr (matching prior console.error behavior) so operators piping stdout to
// their log pipeline never see startup/runtime failures mixed with info-level records, and so
// tests reading each stream separately keep working.
const logger = createLogger({ base: { service: 'agentgate' }, errorStream: process.stderr });

// Mutable startup state, closed over by the signal handlers below. Until `gate` is assigned
// (after `await startGate(...)` resolves, near the end of the try block), the broker is not yet
// serving anything: there is nothing for SIGHUP to reload or for SIGINT/SIGTERM to close.
let gate;
let provider;
let recheck;
let reloading = false;
let stopping = false;
// Control-plane mode (AGENTGATE_CONTROL_URL): signed policy bundles replace the local config file.
const controlMode = Boolean(process.env.AGENTGATE_CONTROL_URL);
// The control-plane client (signed bundles, heartbeat, central approvals) is part of the commercial
// edition; the wiring below is the broker's side of it.
const { createBundleClient, createHeartbeat, applyControlReviews, startApprovalSync } = (controlMode && await edition?.loadControlPlane?.()) || {};
let bundleClient;
let stopApprovalSync;
let stopBundlePolling;
let stopHeartbeat;
let heartbeat;
let bootPolicy;
let period;
// Local revocation list (AGENTGATE_REVOCATIONS_FILE), re-read on SIGHUP and, by default, whenever
// the file's modification time changes (polled every AGENTGATE_REVOCATIONS_POLL_MS, default 5000;
// 0 disables polling); static-config mode only. A rejected re-read keeps the previous list.
const revocationsFile = process.env.AGENTGATE_REVOCATIONS_FILE;
let localRevocations = new Set();
let revocationsPoll;
let revocationsSeen;
// Identity of the file as last loaded; the poller compares against it. Taken at load time (not
// when the poller is armed) so a change made right after `broker.listening` is never missed.
const revocationsStamp = () => { try { const info = statSync(revocationsFile); return `${info.mtimeMs}:${info.size}:${info.ino}`; } catch { return undefined; } };
const revocationsPollMs = Number(process.env.AGENTGATE_REVOCATIONS_POLL_MS ?? 5000);
if (!Number.isInteger(revocationsPollMs) || revocationsPollMs < 0) throw new Error('AGENTGATE_REVOCATIONS_POLL_MS must be a non-negative integer');
const reloadRevocations = (reason) => {
  try {
    revocationsSeen = revocationsStamp();
    localRevocations = loadRevocationsFile(revocationsFile);
    logger.info('revocations.reloaded', { entries: localRevocations.size, reason });
  } catch (error) {
    // Keep enforcing the previous list rather than dropping revocations.
    logger.error('revocations.reload_rejected', { message: error.message, reason });
  }
};

// Registered before any `await` in this module (in particular before the ruleset check and
// startGate, both of which can take real wall-clock time) so a signal arriving during startup is
// handled by us rather than falling through to the OS default disposition, which terminates the
// process for SIGHUP/SIGINT/SIGTERM. `broker.listening` (logged only once startGate resolves)
// remains the true readiness signal; every handler below checks `gate` and behaves safely if it
// fires before that point.
process.on('SIGHUP', () => {
  if (controlMode) { logger.warn('config.reload_ignored_control_plane', { reason: 'policy comes from signed control-plane bundles' }); return; }
  if (!gate) { logger.warn('config.reload_ignored', { reason: 'daemon has not finished starting' }); return; }
  if (reloading) { logger.warn('config.reload_skipped', { reason: 'a reload is already in progress' }); return; }
  if (revocationsFile) reloadRevocations('sighup');
  reloading = true;
  reloadConfig({
    gate, provider, logger,
    load: () => loadConfig(process.env.AGENTGATE_CONFIG || 'config.local.json'),
    skipRulesetCheck: process.env.AGENTGATE_SKIP_RULESET_CHECK === '1',
    isStopping: () => stopping
  }).finally(() => { reloading = false; });
});

const shutdown = async () => {
  if (stopping) return;
  stopping = true;
  if (!gate) {
    // Startup (config load, the boot-time ruleset check, or startGate itself) is still in
    // flight and nothing has bound a port or taken the state-directory lock through this gate
    // yet, so there is nothing to close. Exit immediately instead of waiting on whatever
    // in-flight async step happens to be running, matching the previous (pre-handler) default
    // disposition of an immediate exit on these signals.
    process.exit(0);
  }
  clearInterval(recheck);
  clearInterval(revocationsPoll);
  stopApprovalSync?.();
  stopBundlePolling?.();
  stopHeartbeat?.();
  await gate.close();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Reads an owner-only secret/key file; never logs its contents.
const brokerVersion = (() => {
  try { return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version; } catch { return undefined; }
})();

function readOwnerOnly(path, name) {
  if ((statSync(path).mode & 0o077) !== 0) throw new Error(`${name} must be owner-only (chmod 600)`);
  return readFileSync(path, 'utf8');
}

try {
  // AGENTGATE_PROVIDER selects the adapter (github by default); the loaded config's `provider`
  // must agree (checked below), so a GitLab policy is never served through a GitHub credential.
  const providerKind = process.env.AGENTGATE_PROVIDER || 'github';
  if (!['github', 'gitlab'].includes(providerKind)) throw new Error('AGENTGATE_PROVIDER must be "github" or "gitlab"');
  if (providerKind === 'gitlab') {
    provider = new GitLab({
      baseUrl: process.env.AGENTGATE_GITLAB_URL, refreshTokenFile: process.env.AGENTGATE_GITLAB_REFRESH_TOKEN_FILE,
      clientId: process.env.AGENTGATE_GITLAB_CLIENT_ID,
      clientSecret: process.env.AGENTGATE_GITLAB_CLIENT_SECRET_FILE ? readOwnerOnly(process.env.AGENTGATE_GITLAB_CLIENT_SECRET_FILE, 'AGENTGATE_GITLAB_CLIENT_SECRET_FILE').trim() : undefined
    });
  } else provider = new GitHub({ appId: process.env.GITHUB_APP_ID, signer: signerFromEnv() });
  // Fail closed before anything else runs: every broker path below (ruleset checks, the mirror's
  // token fetch, and the Git/API/LFS/Actions-log routes startGate registers) depends on the full
  // provider interface, so a provider missing a method should stop startup with a clear error
  // rather than fail confusingly on the first request that needs it. GitLab offers no LFS.
  assertProvider(provider, { capabilities: providerKind === 'gitlab' ? ['git', 'api', 'logs'] : ['git', 'api', 'lfs', 'logs'] });
  // Fleet mode (AGENTGATE_CLIENT_AUTH=assertion): no shared workspace token; each request's bearer
  // must be the token its signed runtime assertion is bound to, so one broker serves many workspaces.
  const fleet = process.env.AGENTGATE_CLIENT_AUTH === 'assertion';
  if (process.env.AGENTGATE_CLIENT_AUTH !== undefined && !fleet && process.env.AGENTGATE_CLIENT_AUTH !== 'static') throw new Error('AGENTGATE_CLIENT_AUTH must be "static" or "assertion"');
  if (fleet && process.env.AGENTGATE_CLIENT_TOKEN_FILE) throw new Error('AGENTGATE_CLIENT_AUTH=assertion takes no AGENTGATE_CLIENT_TOKEN_FILE; every workspace token is bound by its assertion');
  const clientToken = process.env.AGENTGATE_CLIENT_TOKEN_FILE ? loadClientToken(process.env.AGENTGATE_CLIENT_TOKEN_FILE) : undefined;
  if (!clientToken && !fleet && process.env.AGENTGATE_ALLOW_UNAUTHENTICATED !== '1') {
    throw new Error('AGENTGATE_CLIENT_TOKEN_FILE is required (set AGENTGATE_ALLOW_UNAUTHENTICATED=1 only for local demos, or AGENTGATE_CLIENT_AUTH=assertion for fleet mode)');
  }
  const clientAuth = fleet ? 'assertion' : clientToken ? 'static' : 'none';
  const skipRulesetCheck = process.env.AGENTGATE_SKIP_RULESET_CHECK === '1';
  const checkRulesets = async (candidate) => {
    if (skipRulesetCheck) return;
    const failures = await verifyProtectedBranches(candidate, provider);
    if (failures.length) {
      throw new Error(`GitHub rules missing: ${failures.map((item) => `${item.repository}:${item.branch} needs ${item.missing.join(', ')}`).join('; ')}`);
    }
  };
  let config;
  let policyExpired = false;
  let policyExpiresAt;
  let rulesetsChecked = false;
  if (controlMode) {
    if (!createBundleClient) requireEdition('AGENTGATE_CONTROL_URL (control-plane mode)');
    for (const name of ['AGENTGATE_BROKER_ID', 'AGENTGATE_CONTROL_TOKEN_FILE', 'AGENTGATE_CONTROL_KEYS_FILE']) {
      if (!process.env[name]) throw new Error(`${name} is required when AGENTGATE_CONTROL_URL is set`);
    }
    let keys;
    try { keys = JSON.parse(readOwnerOnly(process.env.AGENTGATE_CONTROL_KEYS_FILE, 'AGENTGATE_CONTROL_KEYS_FILE')); } catch (error) {
      throw new Error(error instanceof SyntaxError ? 'AGENTGATE_CONTROL_KEYS_FILE must be JSON { kid: publicKeyPem }' : error.message);
    }
    const pollMs = Number(process.env.AGENTGATE_CONTROL_POLL_MS || 60_000);
    if (!Number.isInteger(pollMs) || pollMs < 1000 || pollMs > 3_600_000) throw new Error('AGENTGATE_CONTROL_POLL_MS must be between 1000 and 3600000');
    const controlToken = readOwnerOnly(process.env.AGENTGATE_CONTROL_TOKEN_FILE, 'AGENTGATE_CONTROL_TOKEN_FILE').trim();
    // Audit anchoring: every 60 s the broker reports its audit-chain head (same URL, token, and
    // http override as bundle polling). Built before the first poll so config errors stop startup.
    heartbeat = createHeartbeat({
      controlUrl: process.env.AGENTGATE_CONTROL_URL,
      brokerId: process.env.AGENTGATE_BROKER_ID,
      token: controlToken,
      allowInsecure: process.env.AGENTGATE_CONTROL_ALLOW_HTTP === '1',
      logger,
      snapshot: () => ({ version: brokerVersion, policyVersion: bundleClient.policyVersion, auditHead: gate.state.chainHead, uptimeSeconds: Math.round(process.uptime()) })
    });
    bundleClient = createBundleClient({
      controlUrl: process.env.AGENTGATE_CONTROL_URL,
      brokerId: process.env.AGENTGATE_BROKER_ID,
      token: controlToken,
      keys,
      allowInsecure: process.env.AGENTGATE_CONTROL_ALLOW_HTTP === '1',
      statePath: resolve(process.env.AGENTGATE_STATE_DIR || '.agentgate', 'bundle-state.json'),
      logger,
      // Same path as a SIGHUP reload (ruleset check, then gate.reload validation). Throwing keeps
      // the client from recording the version as accepted. The client aborts `signal` when the
      // apply times out, and reloadConfig then refuses to apply late.
      onPolicy: async (next, _version, { expiresAt, signal } = {}) => {
        if (!gate) {
          if (next === null) { bootPolicy = null; return; }
          // Boot: run the checks startGate and the startup ruleset check would, before the client
          // records the version, so a bundle this broker cannot serve is never persisted.
          if (next.identity?.mode === 'assertion' && !clientToken && !fleet) throw new Error('identity.mode "assertion" requires a workspace client token');
          if (fleet && next.identity?.mode !== 'assertion') throw new Error('AGENTGATE_CLIENT_AUTH=assertion requires identity.mode "assertion"');
          await checkRulesets(next);
          if (signal?.aborted) throw new Error('policy apply timed out');
          bootPolicy = { config: next, expiresAt };
          return;
        }
        if (next === null) { gate.expirePolicy(); return; }
        const result = await reloadConfig({ gate, provider, logger, load: () => next, skipRulesetCheck, isStopping: () => stopping || Boolean(signal?.aborted), reloadOptions: { expiresAt } });
        if (result !== 'applied') throw new Error(`policy bundle not applied (${result})`);
      },
      onRevocations: () => {},
      // Central approval decisions: applied with every local check (policy hash, self-approval,
      // duplicate reviewer, reviewerSources, expiry). Before the gate exists there is nothing to
      // apply; the same version is re-served and applied once the gate is up.
      onReviews: (reviews, version) => {
        if (!gate) return;
        applyControlReviews({ state: gate.state, policyHash: gate.policyHash, brokerId: process.env.AGENTGATE_BROKER_ID, reviews, version, logger });
      }
    });
    period = pollMs;
    const restored = bundleClient.restore();
    await bundleClient.pollOnce();
    if (bootPolicy) {
      ({ config, expiresAt: policyExpiresAt } = bootPolicy);
      rulesetsChecked = true;
    } else if (restored.config) {
      config = validateConfig(structuredClone(restored.config));
      policyExpired = restored.expired;
      policyExpiresAt = restored.expiresAt;
    } else throw new Error('no valid signed policy bundle is available from the control plane; refusing to start');
    if (config.identity?.mode === 'assertion' && !bundleClient.revocationsFresh()) {
      throw new Error('no current signed revocation list is available from the control plane; refusing to start in assertion mode');
    }
    if (revocationsFile) throw new Error('AGENTGATE_REVOCATIONS_FILE is not used in control-plane mode (revocations come from signed bundles)');
  } else {
    config = loadConfig(process.env.AGENTGATE_CONFIG || 'config.local.json');
    if (revocationsFile) { revocationsSeen = revocationsStamp(); localRevocations = loadRevocationsFile(revocationsFile); }
  }
  if ((config.provider ?? 'github') !== providerKind) throw new Error(`config provider "${config.provider ?? 'github'}" does not match AGENTGATE_PROVIDER "${providerKind}"`);
  if (!rulesetsChecked) await checkRulesets(config);
  const port = Number(process.env.AGENTGATE_PORT || 7432);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('AGENTGATE_PORT must be between 1 and 65535');
  const maxBodyMiB = Number(process.env.AGENTGATE_MAX_BODY_MIB || 2048);
  if (!Number.isInteger(maxBodyMiB) || maxBodyMiB < 1 || maxBodyMiB > 4096) throw new Error('AGENTGATE_MAX_BODY_MIB must be between 1 and 4096');
  const certPath = process.env.AGENTGATE_TLS_CERT_FILE;
  const keyPath = process.env.AGENTGATE_TLS_KEY_FILE;
  if (Boolean(certPath) !== Boolean(keyPath)) throw new Error('Set both AGENTGATE_TLS_CERT_FILE and AGENTGATE_TLS_KEY_FILE');
  const tls = certPath ? { cert: readFileSync(certPath), key: readFileSync(keyPath) } : undefined;
  if (!tls && !['127.0.0.1', '::1', 'localhost'].includes(process.env.AGENTGATE_HOST || '127.0.0.1') && process.env.AGENTGATE_ALLOW_PLAINTEXT !== '1') {
    throw new Error('TLS is required when listening beyond loopback (set AGENTGATE_ALLOW_PLAINTEXT=1 to override)');
  }
  // Beyond loopback the listener address (e.g. 0.0.0.0) is not what workspaces dial, so LFS
  // transfer hrefs need the explicit public origin.
  if (!['127.0.0.1', '::1', 'localhost'].includes(process.env.AGENTGATE_HOST || '127.0.0.1') && !process.env.AGENTGATE_PUBLIC_URL) {
    throw new Error('AGENTGATE_PUBLIC_URL is required when AGENTGATE_HOST is not loopback (e.g. https://agentd:7432)');
  }
  // Empty values mean "use the default", so Compose can pass these through as ${VAR:-}.
  let lfsHosts;
  if (process.env.AGENTGATE_LFS_HOSTS) {
    lfsHosts = process.env.AGENTGATE_LFS_HOSTS.split(',').map((item) => item.trim());
    if (!lfsHosts.every(isLfsHost)) throw new Error('AGENTGATE_LFS_HOSTS must be comma-separated lowercase DNS hostnames without ports or wildcards');
  }
  let lfsMaxObjectBytes;
  if (process.env.AGENTGATE_LFS_MAX_OBJECT_MIB) {
    const mib = Number(process.env.AGENTGATE_LFS_MAX_OBJECT_MIB);
    if (!Number.isInteger(mib) || mib < 1 || mib > 5120) throw new Error('AGENTGATE_LFS_MAX_OBJECT_MIB must be between 1 and 5120');
    lfsMaxObjectBytes = mib * 1024 * 1024;
  }
  const maxConcurrent = Number(process.env.AGENTGATE_MAX_CONCURRENT || 4);
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 64) throw new Error('AGENTGATE_MAX_CONCURRENT must be between 1 and 64');
  const lfsMaxTransfers = Number(process.env.AGENTGATE_LFS_MAX_TRANSFERS || 8);
  if (!Number.isInteger(lfsMaxTransfers) || lfsMaxTransfers < 1 || lfsMaxTransfers > 64) throw new Error('AGENTGATE_LFS_MAX_TRANSFERS must be between 1 and 64');
  const rateCapacity = Number(process.env.AGENTGATE_RATE_CAPACITY || 60);
  if (!Number.isInteger(rateCapacity) || rateCapacity < 1 || rateCapacity > 10_000) throw new Error('AGENTGATE_RATE_CAPACITY must be between 1 and 10000');
  const rateRefillPerSecond = Number(process.env.AGENTGATE_RATE_REFILL_PER_SECOND || 2);
  // Per-runtime (assertion jti) budget; defaults to the per-address budget.
  const runtimeRateLimit = { capacity: Number(process.env.AGENTGATE_RUNTIME_RATE_CAPACITY || rateCapacity), refillPerSecond: Number(process.env.AGENTGATE_RUNTIME_RATE_REFILL_PER_SECOND || rateRefillPerSecond) };
  if (!Number.isFinite(runtimeRateLimit.capacity) || runtimeRateLimit.capacity < 1 || !Number.isFinite(runtimeRateLimit.refillPerSecond) || runtimeRateLimit.refillPerSecond <= 0) throw new Error('AGENTGATE_RUNTIME_RATE_CAPACITY and AGENTGATE_RUNTIME_RATE_REFILL_PER_SECOND must be positive numbers');
  if (!(rateRefillPerSecond > 0)) throw new Error('AGENTGATE_RATE_REFILL_PER_SECOND must be greater than 0');
  const auditMaxMiB = Number(process.env.AGENTGATE_AUDIT_MAX_MIB || 64);
  if (!Number.isInteger(auditMaxMiB) || auditMaxMiB < 1) throw new Error('AGENTGATE_AUDIT_MAX_MIB must be a positive integer');
  const auditMaxFiles = Number(process.env.AGENTGATE_AUDIT_MAX_FILES || 20);
  if (!Number.isInteger(auditMaxFiles) || auditMaxFiles < 1) throw new Error('AGENTGATE_AUDIT_MAX_FILES must be a positive integer');
  // Slack (and most webhook) URLs are bearer credentials embedded in the URL itself, so they get
  // the same file-based, owner-only treatment as the client token and audit sink token, and are
  // never logged. AGENTGATE_APPROVAL_WEBHOOK_URL_FILE, when set, takes precedence over the raw
  // AGENTGATE_APPROVAL_WEBHOOK_URL value.
  const webhookUrlPath = process.env.AGENTGATE_APPROVAL_WEBHOOK_URL_FILE;
  let webhookUrl = process.env.AGENTGATE_APPROVAL_WEBHOOK_URL;
  if (webhookUrlPath) {
    if ((statSync(webhookUrlPath).mode & 0o077) !== 0) throw new Error('AGENTGATE_APPROVAL_WEBHOOK_URL_FILE must be owner-only (chmod 600)');
    webhookUrl = readFileSync(webhookUrlPath, 'utf8').trim();
  }
  // Shared with approval-web only: authenticates its admin-socket requests so agentd accepts
  // `oidc:` reviewers from it and from nothing else. Unset, every `oidc:` reviewer is rejected.
  const adminSecret = process.env.AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_FILE ? readAdminSecret(process.env.AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_FILE) : undefined;
  const notify = createNotifier({ url: webhookUrl, approvalUrl: process.env.AGENTGATE_APPROVAL_PUBLIC_URL, logger });
  let metrics;
  if (process.env.AGENTGATE_METRICS_PORT) {
    const metricsPort = Number(process.env.AGENTGATE_METRICS_PORT);
    if (!Number.isInteger(metricsPort) || metricsPort < 1 || metricsPort > 65535) throw new Error('AGENTGATE_METRICS_PORT must be between 1 and 65535');
    // Loopback by default. A non-loopback host is only safe on a monitoring-only network that
    // excludes the workspace (see compose.yaml and docs/operations.md "Monitoring"); this is not enforced
    // here because the daemon cannot see the surrounding network topology.
    metrics = { host: process.env.AGENTGATE_METRICS_HOST || '127.0.0.1', port: metricsPort };
  }
  // Repository mirrors back pre-forward content scanning (repositories[].scan). The read token is
  // handed to git only as an http.extraHeader value through GIT_CONFIG_* env, never argv or a URL.
  const mirror = new Mirror({
    root: mirrorDirectory(process.env),
    fetchRemote: async (repository) => typeof provider.mirrorRemote === 'function' ? provider.mirrorRemote(repository) : ({
      url: `https://github.com/${repository.name}.git`,
      extraHeader: `Authorization: Basic ${Buffer.from(`x-access-token:${await provider.token(repository, 'read')}`).toString('base64')}`
    })
  });
  gate = await startGate({ config, provider, mirror, stateDirectory: resolve(process.env.AGENTGATE_STATE_DIR || '.agentgate'), host: process.env.AGENTGATE_HOST || '127.0.0.1', port, maxBodyBytes: maxBodyMiB * 1024 * 1024, clientToken, clientAuth, tls, maxConcurrent, lfsMaxTransfers,
    rateLimit: { capacity: rateCapacity, refillPerSecond: rateRefillPerSecond }, runtimeRateLimit,
    stateOptions: { maxAuditBytes: auditMaxMiB * 1024 * 1024, maxAuditFiles: auditMaxFiles },
    metrics,
    ...(controlMode ? { revocations: bundleClient.revocations, policyExpired, policyExpiresAt } : { revocations: () => localRevocations }),
    ...(process.env.AGENTGATE_AUDIT_CHECKPOINT_PATH ? { auditCheckpointPath: process.env.AGENTGATE_AUDIT_CHECKPOINT_PATH } : {}),
    notify,
    adminSecret,
    // Origin workspaces use to reach the broker, embedded in rewritten Git LFS transfer hrefs.
    // Defaults to the listener URL; Compose sets https://agentd:7432.
    ...(lfsHosts ? { lfsHosts } : {}),
    ...(lfsMaxObjectBytes ? { lfsMaxObjectBytes } : {}),
    ...(process.env.AGENTGATE_PUBLIC_URL ? { publicUrl: process.env.AGENTGATE_PUBLIC_URL } : {}),
    logger });
  logger.info('broker.listening', { url: gate.url, adminSocket: gate.adminSocket, metricsUrl: gate.metricsUrl });
  // Always recheck against the live config (gate.config), not the object loaded at startup: a
  // SIGHUP reload can add repositories/protectedBranches that this interval is the one to catch.
  // Never start a recheck while the previous one is still running.
  let rechecking = false;
  recheck = setInterval(() => {
    if (rechecking) return;
    rechecking = true;
    verifyProtectedBranches(gate.config, provider)
      .then((failures) => { if (failures.length) logger.warn('rulesets.drift', { failures }); })
      .catch((error) => logger.warn('rulesets.recheck_failed', { message: error.message }))
      .finally(() => { rechecking = false; });
  }, 3600_000);
  recheck.unref();
  if (revocationsFile && revocationsPollMs > 0) {
    revocationsPoll = setInterval(() => {
      const current = revocationsStamp();
      if (current === revocationsSeen) return;
      revocationsSeen = current;
      reloadRevocations('poll');
    }, revocationsPollMs);
    revocationsPoll.unref();
  }
  if (bundleClient) {
    stopBundlePolling = bundleClient.start(period);
    // Publish pending approvals to the control plane and pull decisions promptly (every 5 s while
    // anything is pending), so a central review lands well within one bundle poll period.
    const sync = startApprovalSync({ state: gate.state, policyHash: () => gate.policyHash, client: bundleClient, logger });
    stopApprovalSync = sync.stop;
    sync.tick().catch(() => {});
  }
  if (heartbeat) { heartbeat.sendOnce(); stopHeartbeat = heartbeat.start(60_000); }
} catch (error) {
  logger.error('broker.start_failed', { message: error.message });
  process.exitCode = 1;
}
