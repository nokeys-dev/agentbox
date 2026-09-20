import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { auditFiles, verifyChain } from '../src/audit-chain.js';

const directory = resolve(process.argv[2] || process.env.AGENTGATE_STATE_DIR || '.agentgate');
let previous;
let total = 0;
for (const file of auditFiles(directory)) {
  const lines = readFileSync(file, 'utf8').split('\n');
  if (!previous && lines[0]) {
    let first;
    try { first = JSON.parse(lines[0]); } catch {
      console.error(`FAIL ${file}:1 invalid JSON`);
      process.exit(1);
    }
    previous = { seq: first.seq - 1, hash: first.prevHash };
    if (first.seq !== 1) console.warn(`WARN chain starts at seq ${first.seq}; earlier files were rotated out (verify against the forwarded copy)`);
  }
  const result = verifyChain(lines, previous);
  if (!result.ok) {
    console.error(`FAIL ${file}:${result.line} ${result.reason}`);
    process.exit(1);
  }
  previous = result.head;
  total += result.count;
}
// Rotated files may have been evicted; the first remaining file then starts mid-chain.
console.log(`OK ${total} records head ${previous ? `${previous.seq}:${previous.hash}` : 'empty'}`);
