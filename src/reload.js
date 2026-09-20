import { verifyProtectedBranches } from './rulesets.js';

// One SIGHUP reload attempt. Never throws: reload failures must never crash or stop the daemon,
// and the previous policy keeps serving.
export async function reloadConfig({ gate, provider, logger, load, skipRulesetCheck = false, isStopping = () => false, verify = verifyProtectedBranches, reloadOptions }) {
  try {
    const next = load();
    if (!skipRulesetCheck) {
      const failures = await verify(next, provider);
      if (failures.length) {
        logger.error('rulesets.reload_blocked', { failures });
        return 'blocked';
      }
    }
    // A SIGINT/SIGTERM may have arrived while the ruleset check was awaiting GitHub; by now the
    // gate is closing (or closed, with its state lock released), so do not apply or audit a reload.
    if (isStopping()) {
      logger.warn('config.reload_skipped', { reason: 'daemon is stopping' });
      return 'stopping';
    }
    gate.reload(next, reloadOptions);
    return 'applied';
  } catch (error) {
    // A RULESET_CHECK_FAILED GateError means verifyProtectedBranches could not reach GitHub;
    // that is a ruleset problem, not a config problem. Everything else is a rejected config:
    // most commonly load()'s own validateConfig call throwing on a malformed file before
    // gate.reload is even invoked, but this also covers gate.reload rejecting the object
    // (which additionally logs/audits its own config.reload_rejected).
    if (error.code === 'RULESET_CHECK_FAILED') logger.error('rulesets.reload_blocked', { message: error.message });
    else logger.error('config.reload_rejected', { message: error.message });
    return 'rejected';
  }
}
