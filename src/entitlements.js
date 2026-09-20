import { readFileSync, statSync } from 'node:fs';
import { edition } from './extensions.js';

// Entitlement sources compile a runtime's enterprise context (directory groups, GitHub team
// membership, catalog ownership, task elevation) into one envelope that policy rules can require.
// A failing source never throws out of envelope(): its name is recorded in `errors`, and policy
// treats any error as "every rule with requires does not match" (fail closed).

export const ELEVATION_SYSTEMS = ['jira', 'servicenow', 'pagerduty'];
export const GITHUB_ORG_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
export const GITHUB_TEAM_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9_.-]{0,99})$/;
const LIST_FIELDS = ['teams', 'groups', 'owns'];
// Envelope fields a failing source makes unknown. Directory and team sources can each supply
// team/group/ownership data, so either failing makes all three unknown.
const MEMBERSHIP_FIELDS = ['teams', 'groups', 'owns'];
const ALL_FIELDS = [...MEMBERSHIP_FIELDS, ...ELEVATION_SYSTEMS.map((system) => `elevation:${system}`)];
const MAX_CACHE_ENTRIES = 10_000;

const stringList = (value) => Array.isArray(value) && value.length <= 1000 && value.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 256);

export function staticSource({ path }) {
  return {
    name: 'static',
    provides: MEMBERSHIP_FIELDS,
    resolve: async (runtime) => {
      // Re-read on every (uncached) resolve so a scheduled export is picked up without a reload.
      // Malformed JSON or entries reject, which records a source error instead of crashing.
      const data = JSON.parse(readFileSync(path, 'utf8'));
      if (!data || typeof data !== 'object' || !data.humans || typeof data.humans !== 'object' || Array.isArray(data.humans)) throw new Error('invalid directory');
      const human = String(runtime.human ?? '').toLowerCase();
      const key = Object.keys(data.humans).find((item) => item.toLowerCase() === human);
      const entry = key === undefined ? {} : data.humans[key];
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('invalid directory entry');
      const result = {};
      for (const field of LIST_FIELDS) {
        const value = entry[field] ?? [];
        if (!stringList(value)) throw new Error('invalid directory entry');
        result[field] = field === 'owns' ? value.map((item) => item.toLowerCase()) : value;
      }
      return result;
    }
  };
}

export function githubTeamsSource({ provider, org, installationId, teams }) {
  if (typeof org !== 'string' || !GITHUB_ORG_PATTERN.test(org)) throw new Error('githubTeams.org is invalid');
  if (!Number.isSafeInteger(installationId) || installationId <= 0) throw new Error('githubTeams.installationId must be a positive integer');
  if (!Array.isArray(teams) || !teams.every((slug) => typeof slug === 'string' && GITHUB_TEAM_SLUG_PATTERN.test(slug))) throw new Error('githubTeams.teams must be team slugs');
  return {
    name: 'github-teams',
    provides: MEMBERSHIP_FIELDS,
    resolve: async (runtime) => {
      // ghLogin only ever comes from a verified assertion; without it there is no membership to check.
      // Membership cannot be established, so team requirements are unknown (not unsatisfied).
      if (typeof runtime.ghLogin !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(runtime.ghLogin)) return { teams: [], unknown: ['teams'] };
      const active = [];
      for (const slug of teams) {
        const response = await provider.apiOrg({ installationId, path: `orgs/${org}/teams/${slug}/memberships/${encodeURIComponent(runtime.ghLogin)}`, permissions: { members: 'read' } });
        if (response.status === 404) { await response.body?.cancel(); continue; }
        if (response.status !== 200) { await response.body?.cancel(); throw new Error(`github teams ${response.status}`); }
        if ((await response.json())?.state === 'active') active.push(slug);
      }
      return { teams: active };
    }
  };
}

// Owner-only secret file, same rule as the client token and webhook URL files.
export function readTokenFile(path, label = 'entitlements.jira.tokenFile') {
  if ((statSync(path).mode & 0o077) !== 0) throw new Error(`${label} must be owner-only (chmod 600)`);
  const token = readFileSync(path, 'utf8').trim();
  if (!/^[\x21-\x7e]{1,4096}$/.test(token)) throw new Error(`${label} must hold a nonempty printable token`);
  return token;
}

// Cache key tagged with the identity mode so a static runtimeId can never collide with a jti.
export function envelopeKey(runtime) {
  if (typeof runtime?.jti === 'string') return `assertion:${runtime.jti}`;
  return typeof runtime?.runtimeId === 'string' ? `static:${runtime.runtimeId}` : undefined;
}

export function createEntitlements({ sources, ttlMs = 300_000, errorTtlMs = Math.min(ttlMs, 30_000), now = Date.now, onSourceError = () => {}, maxEntries = MAX_CACHE_ENTRIES }) {
  const cache = new Map();
  const inflight = new Map();
  const store = (key, entry) => {
    cache.delete(key);
    if (cache.size >= maxEntries) {
      const current = now();
      for (const [candidate, value] of cache) if (value.expiresAt <= current) cache.delete(candidate);
      // Still full: evict oldest-inserted entries (Map iteration order) until there is room.
      for (const candidate of cache.keys()) { if (cache.size < maxEntries) break; cache.delete(candidate); }
    }
    cache.set(key, entry);
  };
  const resolve = async (runtime, key) => {
    // No default mode: a runtime without a mode claim leaves modes requirements unknown.
    const envelope = { teams: [], groups: [], owns: [], ...(typeof runtime?.mode === 'string' ? { mode: runtime.mode } : {}), errors: [], unknown: [] };
    const unknown = new Set();
    const results = await Promise.allSettled(sources.map((source) => Promise.resolve().then(() => source.resolve(runtime))));
    results.forEach((result, index) => {
      const value = result.value;
      const valid = result.status === 'fulfilled' && value && typeof value === 'object' &&
        [...LIST_FIELDS, 'unknown'].every((field) => value[field] === undefined || stringList(value[field]));
      if (!valid) {
        envelope.errors.push(sources[index].name);
        for (const field of sources[index].provides ?? ALL_FIELDS) unknown.add(field);
        try { onSourceError(sources[index].name); } catch { /* Reporting must never break resolution. */ }
        return;
      }
      for (const field of LIST_FIELDS) envelope[field].push(...(value[field] ?? []));
      for (const field of value.unknown ?? []) unknown.add(field);
      if (value.elevation) envelope.elevation = value.elevation;
    });
    for (const field of LIST_FIELDS) envelope[field] = [...new Set(envelope[field])].sort();
    envelope.unknown = [...unknown].sort();
    // Errors are cached briefly so an outage neither hammers the source nor pins stale state.
    if (key !== undefined) store(key, { envelope, expiresAt: now() + (envelope.errors.length ? errorTtlMs : ttlMs) });
    return envelope;
  };
  return {
    async envelope(runtime) {
      const key = envelopeKey(runtime);
      const hit = key === undefined ? undefined : cache.get(key);
      if (hit && hit.expiresAt > now()) return hit.envelope;
      if (key === undefined) return resolve(runtime, key);
      // Concurrent requests for the same runtime share one in-flight resolution.
      if (!inflight.has(key)) inflight.set(key, resolve(runtime, key).finally(() => inflight.delete(key)));
      return inflight.get(key);
    },
    get size() { return cache.size; }
  };
}

// Reviewer/audit view of an envelope: the inputs that decided `requires`, never tokens or bodies.
export function envelopeSummary(envelope) {
  return { teams: envelope.teams, groups: envelope.groups, owns: envelope.owns, ...(envelope.mode ? { mode: envelope.mode } : {}), errors: envelope.errors, unknown: envelope.unknown,
    ...(envelope.elevation ? { elevation: envelope.elevation } : {}) };
}

// Builds the entitlements for a validated config, or undefined when no rule uses `requires`
// (then no source is ever queried). Reads the Jira token file here, so a SIGHUP reload re-reads it.
// Membership sources that need no GitHub provider: what an issuer can consult to bound the team a
// developer may delegate. Same settings shape as `entitlements` in the broker config.
export function membershipSources(settings = {}, { fetchImpl = fetch } = {}) {
  const sources = [];
  if (settings.static) sources.push(staticSource({ path: settings.static.path }));
  // Directory sources (Okta, Entra ID) come with the commercial edition; config validation has
  // already refused their settings when it is absent.
  sources.push(...(edition?.membershipSources?.(settings, { fetchImpl, readTokenFile }) ?? []));
  return sources;
}

export function buildEntitlements(config, { provider, fetchImpl = fetch, onSourceError } = {}) {
  const delegation = config.identity?.delegation && config.identity.delegation !== 'off';
  if (!delegation && !config.rules.some((rule) => rule.requires)) return undefined;
  const settings = config.entitlements ?? {};
  const sources = [];
  if (settings.static) sources.push(staticSource({ path: settings.static.path }));
  if (settings.githubTeams) {
    if (typeof provider?.apiOrg !== 'function') throw new Error('entitlements.githubTeams requires a GitHub provider with apiOrg');
    sources.push(githubTeamsSource({ provider, ...settings.githubTeams }));
  }
  // Ticketing (Jira, ServiceNow) and directory (Okta, Entra ID) sources: commercial edition.
  sources.push(...(edition?.elevationSources?.(settings, { fetchImpl, readTokenFile }) ?? []));
  sources.push(...(edition?.membershipSources?.({ ...settings, static: undefined }, { fetchImpl, readTokenFile }) ?? []));
  return createEntitlements({ sources, onSourceError });
}

// Elevation systems that some rule requires but no configured source can supply (such rules can
// never be satisfied; deny/approval rules requiring them simply never apply). Used for a load warning.
export function unsourcedElevations(config) {
  const sourced = new Set(edition?.sourcedElevations?.(config.entitlements ?? {}) ?? []);
  return [...new Set(config.rules.map((rule) => rule.requires?.elevation).filter((system) => system && !sourced.has(system)))].sort();
}
