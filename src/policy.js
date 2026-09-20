import { createHash } from 'node:crypto';

export function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function matches(pattern, value) {
  if (pattern === '*') return true;
  return pattern.endsWith('*') ? value.startsWith(pattern.slice(0, -1)) : pattern === value;
}

// The most restrictive reviewerSources across the given approval rules/decisions: the
// intersection of every list that sets one (possibly empty, which accepts no reviewer at all).
// Omitted when none restrict sources.
function sources(items) {
  const lists = items.map((item) => item.reviewerSources).filter(Array.isArray);
  if (!lists.length) return {};
  return { reviewerSources: ['local', 'oidc', 'control'].filter((source) => lists.every((list) => list.includes(source))) };
}

// Three-valued `requires` evaluation: 'satisfied', 'unsatisfied', or 'unknown'. A check is
// unknown when the data it needs could not be established: a source that supplies it errored or
// reported it unresolved (envelope.unknown holds 'teams'/'groups'/'owns'/'elevation:<system>'), the
// runtime has no mode claim, or there is no envelope at all. Positive evidence still satisfies a
// check. The rule result is unsatisfied if any check is unsatisfied, else unknown if any is unknown.
export function evaluateRequires(requires, envelope) {
  if (!requires) return 'satisfied';
  const unknown = new Set(Array.isArray(envelope?.unknown) ? envelope.unknown : []);
  const results = [];
  const anyOf = (wanted, have, field) => {
    if (!wanted) return;
    if (!envelope) return results.push('unknown');
    if (Array.isArray(have) && wanted.some((item) => have.includes(item))) return results.push('satisfied');
    results.push(unknown.has(field) ? 'unknown' : 'unsatisfied');
  };
  anyOf(requires.teams, envelope?.teams, 'teams');
  anyOf(requires.groups, envelope?.groups, 'groups');
  anyOf(requires.owns, envelope?.owns, 'owns');
  if (requires.modes) {
    results.push(!envelope || typeof envelope.mode !== 'string' ? 'unknown' : requires.modes.includes(envelope.mode) ? 'satisfied' : 'unsatisfied');
  }
  if (requires.elevation) {
    const field = `elevation:${requires.elevation}`;
    results.push(!envelope ? 'unknown' : envelope.elevation?.system === requires.elevation && envelope.elevation?.status === 'active' ? 'satisfied'
      : unknown.has(field) ? 'unknown' : 'unsatisfied');
  }
  return results.includes('unsatisfied') ? 'unsatisfied' : results.includes('unknown') ? 'unknown' : 'satisfied';
}

// Fail closed on unknowns: allow rules participate only when satisfied; deny and approval rules
// participate unless unsatisfied, so an entitlement outage can never drop a restriction and let a
// broader allow through. Participating approval rules are all merged below.
function participates(rule, envelope) {
  const result = evaluateRequires(rule.requires, envelope);
  return rule.effect === 'allow' ? result === 'satisfied' : result !== 'unsatisfied';
}

export function decide(config, action, repository, change, envelope) {
  if (!config.repositories.some((repo) => repo.name === repository)) {
    return { effect: 'deny', rule: 'repository-not-configured' };
  }
  // A fork head is only ever decided as a fork head: it must be a configured fork of this exact
  // repository, and only rules naming it (or '*') apply. Rules without headRepository match
  // same-repository heads only.
  const headRepository = change?.headRepository;
  if (headRepository !== undefined && (!['github.pr.create', 'github.pr.merge', 'gitlab.mr.create', 'gitlab.mr.merge'].includes(action) ||
    !config.repositories.some((repo) => repo.name === headRepository && repo.forkOf === repository))) {
    return { effect: 'deny', rule: 'head-repository-not-configured' };
  }
  const rules = config.rules.filter((rule) => rule.action === action && matches(rule.repository, repository) &&
    (!change || (matches(rule.ref, change.ref) && (!rule.operation || rule.operation === change.operation))) &&
    (headRepository === undefined ? rule.headRepository === undefined : (rule.headRepository === '*' || rule.headRepository === headRepository)) &&
    participates(rule, envelope));
  // Explicit denials always win; an approval requirement also overrides an allow.
  for (const effect of ['deny', 'approval', 'allow']) {
    const matching = rules.filter((candidate) => candidate.effect === effect);
    if (matching.length) {
      return effect === 'approval'
        ? { effect, rule: matching[0].id, requiredApprovals: Math.max(...matching.map((item) => item.approvals ?? 1)), ...sources(matching),
          // Merge methods follow the same most-restrictive merge as reviewerSources: a method is
          // allowed only if every matching approval rule allows it (each defaulting to squash).
          ...(['github.pr.merge', 'gitlab.mr.merge'].includes(action) ? { mergeMethods: ['merge', 'squash', 'rebase'].filter((method) => matching.every((item) => (item.mergeMethods ?? ['squash']).includes(method))) } : {}) }
        : { effect, rule: matching[0].id };
    }
  }
  return { effect: 'deny', rule: 'default-deny' };
}

export function decidePush(config, repository, changes, envelope) {
  const decisions = changes.map((change) => ({ ...change, ...decide(config, 'git.push', repository, change, envelope) }));
  const effect = decisions.some((item) => item.effect === 'deny') ? 'deny'
    : decisions.some((item) => item.effect === 'approval') ? 'approval' : 'allow';
  return { effect, decisions, requiredApprovals: Math.max(0, ...decisions.map((item) => item.requiredApprovals ?? 0)),
    ...sources(decisions.filter((item) => item.effect === 'approval')) };
}
