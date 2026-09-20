import { GateError } from './errors.js';
import { verifyGitlabProtectedBranches } from './gitlab-rulesets.js';

export const REQUIRED_RULES = ['deletion', 'non_fast_forward', 'pull_request'];

// `timeoutMs` bounds the whole check (every branch), not just each request, so a slow GitHub
// cannot make periodic rechecks or bundle applies pile up behind one another.
//
// With `hostedAgents` configured, each protected branch must also require the AgentBox check run
// (`hostedAgents.checkName`) through a required_status_checks rule, and no ruleset governing the
// branch may let a GitHub App (actor_type Integration) bypass it: a hosted agent's own App would
// otherwise merge around the check. Failures are reported per branch; the caller fails closed.
export async function verifyProtectedBranches(config, provider, { timeoutMs = 60_000, requestTimeoutMs = 15_000 } = {}) {
  // GitLab has protected branches instead of rulesets; same contract, same fail-closed behaviour.
  if (provider?.kind === 'gitlab') return verifyGitlabProtectedBranches(config, provider, { timeoutMs, requestTimeoutMs });
  const failures = [];
  const deadline = AbortSignal.timeout(timeoutMs);
  const hosted = config.hostedAgents;
  const rulesetCache = new Map();
  const read = async (repository, path, label) => {
    try {
      const response = await provider.api({ repository, operation: { method: 'GET', path, permissions: { metadata: 'read' } }, signal: AbortSignal.any([deadline, AbortSignal.timeout(requestTimeoutMs)]) });
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new Error(String(response.status));
      }
      return await response.json();
    } catch (error) {
      throw new GateError(502, 'RULESET_CHECK_FAILED', `Could not read GitHub ${label} for ${repository.name} (${error.message})`);
    }
  };
  for (const repository of config.repositories) {
    for (const branch of repository.protectedBranches ?? []) {
      if (deadline.aborted) throw new GateError(502, 'RULESET_CHECK_FAILED', `GitHub rules check exceeded ${timeoutMs} ms`);
      const rules = await read(repository, `rules/branches/${encodeURIComponent(branch)}`, `rules:${branch}`);
      if (!Array.isArray(rules)) throw new GateError(502, 'RULESET_CHECK_FAILED', `Could not read GitHub rules for ${repository.name}:${branch} (shape)`);
      const present = new Set(rules.map((rule) => rule?.type));
      const missing = REQUIRED_RULES.filter((type) => !present.has(type));
      const failure = { repository: repository.name, branch, missing };
      if (hosted) {
        const checks = rules.filter((rule) => rule?.type === 'required_status_checks')
          .flatMap((rule) => rule?.parameters?.required_status_checks ?? []).map((check) => check?.context);
        if (!checks.includes(hosted.checkName)) missing.push(`required_status_checks:${hosted.checkName}`);
        const bypass = [];
        for (const rulesetId of new Set(rules.map((rule) => rule?.ruleset_id).filter((id) => Number.isInteger(id)))) {
          if (!rulesetCache.has(rulesetId)) {
            const ruleset = await read(repository, `rulesets/${rulesetId}`, `ruleset ${rulesetId}`);
            rulesetCache.set(rulesetId, Array.isArray(ruleset?.bypass_actors) ? ruleset.bypass_actors : []);
          }
          for (const actor of rulesetCache.get(rulesetId)) if (actor?.actor_type === 'Integration') bypass.push({ rulesetId, actorId: actor.actor_id, bypassMode: actor.bypass_mode });
        }
        if (bypass.length) failure.bypassActors = bypass;
      }
      if (failure.missing.length || failure.bypassActors) failures.push(failure);
    }
  }
  return failures;
}
