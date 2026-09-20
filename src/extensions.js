import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// AgentBox ships in two editions from one codebase. The open-source edition is everything outside
// enterprise/. The commercial edition adds that directory: the control plane and signed policy
// bundles, central approvals, the issuing service, hosted-agent coverage, the approval UI, and the
// directory and ticketing entitlement sources. When the directory is present its index module is
// loaded here, once, before any importer of this module runs, so core code asks `edition` what is
// available instead of importing commercial modules. Modules under enterprise/ may import core
// modules, never this one, which keeps the load order free of cycles.
const entry = fileURLToPath(new URL('../enterprise/src/index.js', import.meta.url));

export const edition = existsSync(entry) ? (await import(entry)).default : undefined;

// A setting or mode that only the commercial edition implements fails with one clear sentence
// rather than an unknown-key error or a missing module.
export function requireEdition(feature) {
  if (!edition) throw new Error(`${feature} requires the AgentBox commercial edition (https://nokeys.dev)`);
  return edition;
}
