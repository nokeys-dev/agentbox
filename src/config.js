import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { assert } from './errors.js';
import { MAX_SECRET_SCAN_BYTES, SCAN_RULE_IDS, validScanPath } from './scan.js';
import { ELEVATION_SYSTEMS, GITHUB_ORG_PATTERN, GITHUB_TEAM_SLUG_PATTERN } from './entitlements.js';
import { edition, requireEdition } from './extensions.js';

const COMMERCIAL_ENTITLEMENT_KEYS = ['jira', 'servicenow', 'okta', 'entra'];

const nameList = (value, max = 50) => Array.isArray(value) && value.length >= 1 && value.length <= max &&
  value.every((item) => typeof item === 'string' && item.length >= 1 && item.length <= 128);

const httpsUrl = (value) => {
  let url;
  try { url = new URL(value); } catch { return false; }
  return typeof value === 'string' && url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && !/[?#]/.test(value);
};
const absolutePath = (value) => typeof value === 'string' && value.startsWith('/') && value.length <= 4096;

export function validateEntitlements(entitlements) {
  // static and githubTeams are open source. The ticketing and directory sources (jira, servicenow,
  // okta, entra) are validated by the commercial edition, which also supplies them; naming one
  // without it is refused here rather than silently ignored.
  const commercial = edition?.entitlementKeys ?? [];
  for (const key of COMMERCIAL_ENTITLEMENT_KEYS) if (entitlements?.[key] !== undefined && !commercial.includes(key)) requireEdition(`entitlements.${key}`);
  keys(entitlements, ['static', 'githubTeams', ...commercial], 'entitlements');
  if (entitlements.static !== undefined) {
    keys(entitlements.static, ['path'], 'entitlements.static');
    assert(typeof entitlements.static.path === 'string' && entitlements.static.path.startsWith('/') && entitlements.static.path.length <= 4096, 'entitlements.static.path must be an absolute path');
  }
  if (entitlements.githubTeams !== undefined) {
    const teams = entitlements.githubTeams;
    keys(teams, ['org', 'installationId', 'teams'], 'entitlements.githubTeams');
    assert(typeof teams.org === 'string' && GITHUB_ORG_PATTERN.test(teams.org), 'entitlements.githubTeams.org must be a GitHub organization login');
    assert(Number.isSafeInteger(teams.installationId) && teams.installationId > 0, 'entitlements.githubTeams.installationId must be a positive integer');
    assert(nameList(teams.teams) && teams.teams.every((slug) => GITHUB_TEAM_SLUG_PATTERN.test(slug)) && new Set(teams.teams).size === teams.teams.length,
      'entitlements.githubTeams.teams must list 1-50 distinct lowercase team slugs');
  }
  edition?.validateEntitlements?.(entitlements, { assert, keys, nameList, httpsUrl, absolutePath });
}

function validateRequires(requires, id) {
  const label = `requires in ${id}`;
  assert(requires && typeof requires === 'object' && !Array.isArray(requires) && Object.keys(requires).length > 0, `${label} must be a nonempty object`);
  for (const key of Object.keys(requires)) assert(['teams', 'groups', 'owns', 'elevation', 'modes'].includes(key), `Unknown ${label} field: ${key}`);
  for (const field of ['teams', 'groups', 'owns']) {
    assert(requires[field] === undefined || nameList(requires[field]), `${label}: ${field} must list 1-50 strings of at most 128 characters`);
  }
  if (requires.owns) requires.owns = requires.owns.map((item) => item.toLowerCase());
  assert(requires.elevation === undefined || ELEVATION_SYSTEMS.includes(requires.elevation), `${label}: elevation must be one of ${ELEVATION_SYSTEMS.join(', ')}`);
  assert(requires.modes === undefined || (nameList(requires.modes, 3) && requires.modes.every((mode) => ['build', 'operate', 'readonly'].includes(mode))),
    `${label}: modes must list build/operate/readonly`);
}

function validateScan(scan, name) {
  const label = `scan in ${name}`;
  keys(scan, ['secrets', 'blockedPaths', 'maxBlobBytes', 'allowlist'], label);
  assert(scan.secrets === undefined || typeof scan.secrets === 'boolean', `${label}: secrets must be a boolean`);
  assert(scan.blockedPaths === undefined || (Array.isArray(scan.blockedPaths) && scan.blockedPaths.length <= 100 && scan.blockedPaths.every((item) => validScanPath(item, { glob: true }))),
    `${label}: blockedPaths must list up to 100 relative paths, "dir/" prefixes, or "*.ext" suffixes (no "/", "./", "..", or other "*")`);
  assert(scan.maxBlobBytes === undefined || (Number.isSafeInteger(scan.maxBlobBytes) && scan.maxBlobBytes > 0), `${label}: maxBlobBytes must be a positive integer`);
  assert(!(scan.secrets && scan.maxBlobBytes > MAX_SECRET_SCAN_BYTES), `${label}: maxBlobBytes must be at most ${MAX_SECRET_SCAN_BYTES} when secrets is true`);
  if (scan.allowlist !== undefined) {
    assert(Array.isArray(scan.allowlist) && scan.allowlist.length <= 100, `${label}: allowlist must list up to 100 entries`);
    for (const entry of scan.allowlist) {
      keys(entry, ['rule', 'path'], `${label} allowlist entry`);
      assert(SCAN_RULE_IDS.includes(entry.rule), `${label}: allowlist rule must be one of ${SCAN_RULE_IDS.join(', ')}`);
      assert(validScanPath(entry.path, { glob: false }), `${label}: allowlist path must be a relative path without "*", "./", or ".."`);
    }
  }
}

function keys(value, allowed, label) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  for (const key of Object.keys(value)) assert(allowed.includes(key), `Unknown ${label} field: ${key}`);
}

export function validateConfig(config) {
  keys(config, ['identity', 'runtime', 'repositories', 'rules', 'entitlements', 'provider', 'hostedAgents'], 'config');
  // Vendor-hosted agents (Copilot coding agent, Cursor background agents, ...) governed through
  // GitHub webhooks and a required check run; see enterprise/src/hosted-agents.js and docs/hosted-agents.md.
  if (config.hostedAgents !== undefined) {
    const hosted = config.hostedAgents;
    keys(hosted, ['agents', 'checkName'], 'hostedAgents');
    assert(Array.isArray(hosted.agents) && hosted.agents.length >= 1 && hosted.agents.length <= 20, 'hostedAgents.agents must list 1-20 agents');
    const logins = new Set();
    const names = new Set();
    for (const agent of hosted.agents) {
      keys(agent, ['login', 'name'], 'hostedAgents agent');
      assert(typeof agent.login === 'string' && /^[A-Za-z0-9-]{1,39}(\[bot\])?$/.test(agent.login) && !logins.has(agent.login.toLowerCase()), 'hostedAgents.agents[].login must be a unique GitHub login, optionally ending in [bot]');
      assert(typeof agent.name === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(agent.name) && !names.has(agent.name), 'hostedAgents.agents[].name must be a unique short name');
      logins.add(agent.login.toLowerCase());
      names.add(agent.name);
    }
    assert(hosted.checkName === undefined || (typeof hosted.checkName === 'string' && /^[A-Za-z0-9._\/-]{1,64}$/.test(hosted.checkName)), 'hostedAgents.checkName must be a check run name');
    hosted.checkName ??= 'agentbox/policy';
  }
  if (config.entitlements !== undefined) validateEntitlements(config.entitlements);
  // One provider per broker. Repository identifiers and API actions are provider-specific; the
  // daemon refuses to start when its configured adapter does not match this field.
  assert(config.provider === undefined || ['github', 'gitlab'].includes(config.provider), 'provider must be "github" or "gitlab"');
  const provider = config.provider ?? 'github';
  const gitlab = provider === 'gitlab';
  // identity.mode 'static' (the default) serves the single runtime identity in this file.
  // 'assertion' takes the identity from a signed, client-token-bound runtime assertion on every
  // request instead (see assertion.js), so the file must not also name a runtime.
  const identity = config.identity ?? { mode: 'static' };
  assert(identity && typeof identity === 'object' && !Array.isArray(identity) && ['static', 'assertion'].includes(identity.mode), 'identity.mode must be "static" or "assertion"');
  if (identity.mode === 'assertion') {
    keys(identity, ['mode', 'audience', 'issuers', 'delegation'], 'identity');
    assert(config.runtime === undefined, 'runtime must be omitted when identity.mode is "assertion"');
    // Verification-time delegation bound: the assertion's team must be one the entitlement sources
    // report for its human. "enforce" rejects (fail closed on source errors), "audit" records only.
    assert(identity.delegation === undefined || ['off', 'audit', 'enforce'].includes(identity.delegation), 'identity.delegation must be "off", "audit", or "enforce"');
    if (identity.delegation && identity.delegation !== 'off') {
      const sources = config.entitlements ?? {};
      const membership = ['static', 'githubTeams', ...(edition?.membershipKeys ?? [])];
      assert(membership.some((name) => sources[name] !== undefined), `identity.delegation requires a membership entitlement source (${membership.join(', ')})`);
    }
    assert(typeof identity.audience === 'string' && /^[\x21-\x7e]{1,256}$/.test(identity.audience), 'identity.audience must be a nonempty printable string of at most 256 characters');
    assert(Array.isArray(identity.issuers) && identity.issuers.length >= 1 && identity.issuers.length <= 10, 'identity.issuers must list 1-10 issuers');
    const kids = new Set();
    for (const issuer of identity.issuers) {
      keys(issuer, ['kid', 'publicKeyPem'], 'issuer');
      assert(typeof issuer.kid === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(issuer.kid) && !kids.has(issuer.kid), 'Issuer kid values must be unique and match ^[A-Za-z0-9_-]{1,64}$');
      kids.add(issuer.kid);
      let key;
      // createPublicKey also accepts a private key (deriving its public half); refuse that so an
      // issuer private key is never deployed to the broker by mistake.
      try { if (!/PRIVATE KEY/.test(issuer.publicKeyPem)) key = createPublicKey(issuer.publicKeyPem); } catch { /* reported below */ }
      assert(typeof issuer.publicKeyPem === 'string' && key?.asymmetricKeyType === 'ed25519', `Issuer ${issuer.kid} publicKeyPem must be an ed25519 public key`);
    }
  } else {
    keys(identity, ['mode'], 'identity');
    keys(config.runtime, ['human', 'agent', 'runtimeId', 'task'], 'runtime');
    for (const field of ['human', 'agent', 'runtimeId', 'task']) {
      assert(typeof config.runtime[field] === 'string' && config.runtime[field].trim().length > 0 && config.runtime[field].length <= 256,
        `runtime.${field} must be a nonempty string of at most 256 characters`);
    }
  }
  assert(Array.isArray(config.repositories) && config.repositories.length > 0, 'Configure at least one repository');
  const names = new Set();
  const ids = new Set();
  for (const repo of config.repositories) {
    keys(repo, gitlab ? ['name', 'projectId', 'protectedBranches', 'allowedPushOptions', 'allowUnicodeRefs', 'forkOf', 'scan']
      : ['name', 'id', 'installationId', 'allowWorkflowWrites', 'protectedBranches', 'allowedPushOptions', 'allowUnicodeRefs', 'forkOf', 'scan'], 'repository');
    if (repo.scan !== undefined) validateScan(repo.scan, repo.name);
    assert(repo.allowWorkflowWrites === undefined || typeof repo.allowWorkflowWrites === 'boolean', 'allowWorkflowWrites must be a boolean');
    assert(repo.allowUnicodeRefs === undefined || typeof repo.allowUnicodeRefs === 'boolean', 'allowUnicodeRefs must be a boolean');
    // '*' is either the entire pattern (a bare wildcard: matches any option value at all — see
    // README's "Push options" section for why that is dangerous) or, otherwise, may appear only
    // once, as the final character of an exact-match prefix. It must never appear anywhere else
    // (not doubled, not in the middle, not before other characters), since that would silently
    // accept a nonsensical pattern without ever behaving as a wildcard.
    assert(repo.allowedPushOptions === undefined || (Array.isArray(repo.allowedPushOptions) && repo.allowedPushOptions.length <= 32 &&
      repo.allowedPushOptions.every((item) => typeof item === 'string' && /^(\*|[\x21-\x29\x2b-\x7e][\x20-\x29\x2b-\x7e]{0,254}\*?)$/.test(item))),
    'allowedPushOptions must be up to 32 printable strings; "*" may only be a bare wildcard or the single final character of a pattern');
    if (repo.protectedBranches !== undefined) {
      assert(Array.isArray(repo.protectedBranches) && repo.protectedBranches.length <= 20 && repo.protectedBranches.every((branch) =>
        typeof branch === 'string' && /^[A-Za-z0-9_./-]{1,200}$/.test(branch) && !branch.startsWith('refs/') && !branch.startsWith('-') &&
        !branch.includes('..') && branch.split('/').every((part) => part && !part.startsWith('.') && !part.endsWith('.lock'))),
      'protectedBranches must be up to 20 branch names without refs/heads/');
    }
    if (gitlab) {
      // GitLab project paths: group[/subgroup...]/project, at least two segments, no traversal.
      assert(typeof repo.name === 'string' && /^[\w.-]+(\/[\w.-]+)+$/.test(repo.name) && repo.name.length <= 255 && !repo.name.endsWith('.git') &&
        repo.name.split('/').every((part) => !['.', '..'].includes(part) && !part.startsWith('-')),
      `GitLab project names must be GROUP/PROJECT (nested groups allowed) without .git: ${JSON.stringify(typeof repo.name === 'string' ? repo.name.slice(0, 80) : repo.name)}`);
      assert(Number.isSafeInteger(repo.projectId) && repo.projectId > 0, 'projectId must be a positive integer');
      // The mirror and duplicate checks key on `id`; GitLab's numeric project id fills that role.
      repo.id = repo.projectId;
    } else {
      assert(typeof repo.name === 'string' && /^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+$/.test(repo.name) && !repo.name.endsWith('.git'),
        `Repository names must be OWNER/REPO without .git (owner: letters, digits, hyphens): ${JSON.stringify(typeof repo.name === 'string' ? repo.name.slice(0, 80) : repo.name)}`);
      assert(!['.', '..'].includes(repo.name.split('/')[1]), 'Invalid repository name');
      assert(Number.isSafeInteger(repo.id) && repo.id > 0, 'Repository id must be a positive integer');
      assert(Number.isSafeInteger(repo.installationId) && repo.installationId > 0, 'installationId must be a positive integer');
    }
    repo.name = repo.name.toLowerCase();
    assert(!names.has(repo.name) && !ids.has(repo.id), 'Duplicate repository');
    names.add(repo.name);
    ids.add(repo.id);
  }
  // Forks are one level deep: a fork names a configured, non-fork upstream owned by someone else.
  // Upstream PR creation from a fork head is then policy-checked with headRepository (see policy.js).
  for (const repo of config.repositories.filter((item) => item.forkOf !== undefined)) {
    assert(typeof repo.forkOf === 'string', `forkOf in ${repo.name} must be a repository name`);
    repo.forkOf = repo.forkOf.toLowerCase();
    const target = config.repositories.find((item) => item.name === repo.forkOf);
    assert(target && repo.forkOf !== repo.name && repo.forkOf.split('/')[0] !== repo.name.split('/')[0],
      `forkOf in ${repo.name} must name another configured repository with a different owner`);
    assert(target.forkOf === undefined, `forkOf in ${repo.name} must name a repository that is not itself a fork`);
  }
  assert(Array.isArray(config.rules), 'rules must be an array');
  const ruleIds = new Set();
  for (const rule of config.rules) {
    keys(rule, ['id', 'action', 'repository', 'ref', 'operation', 'effect', 'approvals', 'reviewerSources', 'headRepository', 'mergeMethods', 'requires'], 'rule');
    if (rule.requires !== undefined) validateRequires(rule.requires, rule.id);
    assert(typeof rule.id === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(rule.id) && !ruleIds.has(rule.id), 'Rule ids must be unique identifiers');
    ruleIds.add(rule.id);
    const actions = gitlab ? ['git.read', 'git.push', 'gitlab.mr.read', 'gitlab.mr.create', 'gitlab.mr.comment', 'gitlab.pipelines.read', 'gitlab.mr.merge']
      : ['git.read', 'git.push', 'github.pr.read', 'github.pr.create', 'github.pr.comment', 'github.actions.read', 'git.lfs.upload', 'github.pr.merge', 'github.pr.hosted'];
    assert(actions.includes(rule.action), `Invalid action in ${rule.id} for provider ${provider}`);
    // Provider-neutral view of the action's role, so the checks below read the same for both.
    const role = ['github.pr.create', 'gitlab.mr.create'].includes(rule.action) ? 'create' : ['github.pr.merge', 'gitlab.mr.merge'].includes(rule.action) ? 'merge' : rule.action === 'github.pr.hosted' ? 'hosted' : rule.action === 'git.push' ? 'push' : 'read';
    assert(['allow', 'deny', 'approval'].includes(rule.effect), `Invalid effect in ${rule.id}`);
    assert(rule.approvals === undefined || (rule.effect === 'approval' && Number.isInteger(rule.approvals) && rule.approvals >= 1 && rule.approvals <= 5),
      `approvals in ${rule.id} must be an integer 1-5 on an approval rule`);
    assert(rule.reviewerSources === undefined || (rule.effect === 'approval' && Array.isArray(rule.reviewerSources) && rule.reviewerSources.length > 0 &&
      rule.reviewerSources.every((source) => ['local', 'oidc', 'control'].includes(source)) && new Set(rule.reviewerSources).size === rule.reviewerSources.length),
    `reviewerSources in ${rule.id} must be a nonempty list of distinct "local"/"oidc"/"control" values on an approval rule`);
    assert(typeof rule.repository === 'string', `Missing repository in ${rule.id}`);
    rule.repository = rule.repository.toLowerCase();
    assert(rule.repository === '*' || names.has(rule.repository), `Unknown repository in ${rule.id}`);
    if (role === 'read') {
      assert(rule.ref === undefined && rule.operation === undefined && rule.effect !== 'approval', `${rule.action} supports allow/deny without ref or operation`);
    } else {
      assert(typeof rule.ref === 'string' && (rule.ref === '*' || /^refs\/[A-Za-z0-9_./-]+\*?$/.test(rule.ref)), `Invalid ref pattern in ${rule.id}`);
      assert(rule.operation === undefined || ['create', 'update', 'delete'].includes(rule.operation), `Invalid operation in ${rule.id}`);
      if (role === 'create') assert(rule.operation === undefined, `${rule.action} uses a head ref pattern without operation`);
      if (role === 'merge') assert(rule.operation === undefined, `${rule.action} uses a base ref pattern without operation`);
      if (role === 'hosted') assert(rule.operation === undefined, 'github.pr.hosted uses a base ref pattern without operation');
    }
    // Merges land code on (usually protected) base branches, so they are never auto-allowed:
    // every merge needs a human approval pinned to the reviewed head SHA (see github-api.js).
    if (role === 'merge') {
      assert(rule.effect !== 'allow', `${rule.action} in ${rule.id} must use approval or deny`);
      const methods = gitlab ? ['merge', 'squash'] : ['merge', 'squash', 'rebase'];
      assert(rule.mergeMethods === undefined || (Array.isArray(rule.mergeMethods) && rule.mergeMethods.length > 0 &&
        rule.mergeMethods.every((method) => methods.includes(method)) && new Set(rule.mergeMethods).size === rule.mergeMethods.length),
      `Invalid mergeMethods in ${rule.id}: use a nonempty list of distinct ${methods.join('/')}`);
    } else assert(rule.mergeMethods === undefined, `mergeMethods only applies to merge actions (${rule.id})`);
    if (rule.headRepository !== undefined) {
      assert(['create', 'merge'].includes(role) && typeof rule.headRepository === 'string', `headRepository in ${rule.id} is only valid on pull/merge request create or merge actions`);
      rule.headRepository = rule.headRepository.toLowerCase();
      assert(rule.headRepository === '*' || names.has(rule.headRepository), `headRepository in ${rule.id} must be "*" or a configured repository`);
    }
  }
  return config;
}

export function loadConfig(path) {
  return validateConfig(JSON.parse(readFileSync(path, 'utf8')));
}
