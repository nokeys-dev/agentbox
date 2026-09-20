// GitLab equivalent of rulesets.js: each configured protectedBranches entry must be a protected
// branch on the project that forbids direct pushes (every push access level is "No one", 0) and
// force pushes, so changes reach it only through merge requests the broker can gate. Fails closed:
// an unreadable project or branch is RULESET_CHECK_FAILED, never "no rules".
import { GateError } from './errors.js';

export const REQUIRED_PROTECTIONS = ['no-direct-push', 'no-force-push'];

export async function verifyGitlabProtectedBranches(config, provider, { timeoutMs = 60_000, requestTimeoutMs = 15_000 } = {}) {
  const failures = [];
  const deadline = AbortSignal.timeout(timeoutMs);
  for (const repository of config.repositories) {
    for (const branch of repository.protectedBranches ?? []) {
      if (deadline.aborted) throw new GateError(502, 'RULESET_CHECK_FAILED', `GitLab protected branch check exceeded ${timeoutMs} ms`);
      const operation = { method: 'GET', path: `protected_branches/${encodeURIComponent(branch)}` };
      let rule;
      try {
        const response = await provider.api({ repository, operation, signal: AbortSignal.any([deadline, AbortSignal.timeout(requestTimeoutMs)]) });
        if (response.status === 404) { await response.body?.cancel(); failures.push({ repository: repository.name, branch, missing: ['protected'] }); continue; }
        if (response.status !== 200) { await response.body?.cancel(); throw new Error(String(response.status)); }
        rule = await response.json();
        if (!rule || typeof rule !== 'object' || !Array.isArray(rule.push_access_levels)) throw new Error('shape');
      } catch (error) {
        throw new GateError(502, 'RULESET_CHECK_FAILED', `Could not read GitLab protected branch ${repository.name}:${branch} (${error.message})`);
      }
      const missing = [];
      if (!rule.push_access_levels.every((level) => level?.access_level === 0)) missing.push('no-direct-push');
      if (rule.allow_force_push !== false) missing.push('no-force-push');
      if (missing.length) failures.push({ repository: repository.name, branch, missing });
    }
  }
  return failures;
}
