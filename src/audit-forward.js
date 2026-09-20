import { createReadStream, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { auditFiles, GENESIS, lastLine, verifyChain } from './audit-chain.js';

const fail = (code, message) => Object.assign(new Error(message), { code });

function readCheckpoint(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw fail('CHECKPOINT_INVALID', `Unreadable checkpoint ${path}`);
  }
}

function writeCheckpoint(path, head) {
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(head)}\n`, { mode: 0o600, flush: true });
  renameSync(temporary, path);
}

// A file's last line carries its highest seq. Reading only that line (not the whole file) is
// enough to decide whether the file has anything left to forward, without paying to parse
// everything it contains.
function tailSeq(file) {
  const line = lastLine(file);
  if (!line) return 0;
  let record;
  try { record = JSON.parse(line); } catch { throw fail('CHAIN_BROKEN', `Audit chain tail is invalid in ${file}; run npm run audit:verify`); }
  if (!Number.isSafeInteger(record.seq)) throw fail('CHAIN_BROKEN', `Audit chain tail is invalid in ${file}; run npm run audit:verify`);
  return record.seq;
}

export async function forwardOnce({ directory, checkpointPath, send, batchSize = 500 }) {
  const checkpoint = readCheckpoint(checkpointPath) ?? { seq: 0, hash: GENESIS };

  // Files are already oldest-first. A file whose own last record is at or before the checkpoint
  // has nothing pending in it, so it never needs a full read; only its tail is consulted, both to
  // skip it and to know the true highest surviving seq (to catch a wipe or a rewind below).
  let highestSeq = 0;
  const relevantFiles = [];
  for (const file of auditFiles(directory)) {
    const seq = tailSeq(file);
    if (seq > highestSeq) highestSeq = seq;
    if (seq > checkpoint.seq) relevantFiles.push(file);
  }
  if (checkpoint.seq > 0 && highestSeq < checkpoint.seq) {
    throw fail('AUDIT_GAP', `Audit history (highest surviving seq ${highestSeq}) no longer reaches checkpoint seq ${checkpoint.seq}; it was wiped or rewound`);
  }

  let head = checkpoint;
  let sent = 0;
  let batch = [];
  let sawFirstPending = false;

  const flush = async () => {
    if (!batch.length) return;
    await send(batch);
    writeCheckpoint(checkpointPath, head);
    sent += batch.length;
    batch = [];
  };

  for (const file of relevantFiles) {
    const stream = createReadStream(file, { encoding: 'utf8' });
    const rl = createInterface({ input: stream, crlfDelay: Infinity });
    try {
      for await (const line of rl) {
        if (!line) continue;
        let record;
        try { record = JSON.parse(line); } catch { throw fail('CHAIN_BROKEN', `Audit chain invalid in ${file}: invalid JSON`); }
        if (record.seq <= checkpoint.seq) continue; // already forwarded; only reachable in a file straddling the checkpoint
        if (!sawFirstPending) {
          sawFirstPending = true;
          if (record.seq !== checkpoint.seq + 1) {
            throw fail('AUDIT_GAP', `Records ${checkpoint.seq + 1}..${record.seq - 1} were rotated out before forwarding`);
          }
        }
        const verified = verifyChain([line], head);
        if (!verified.ok) throw fail('CHAIN_BROKEN', `Audit chain invalid at pending record ${record.seq}: ${verified.reason}`);
        head = verified.head;
        batch.push(record);
        if (batch.length >= batchSize) await flush();
      }
    } finally {
      rl.close();
      stream.destroy();
    }
  }
  await flush();

  return { sent, head, lagRecords: 0 };
}

export function httpSink({ url, token, fetchImpl = fetch }) {
  if (new URL(url).protocol !== 'https:') throw new Error('Audit sink URL must use https');
  return async (records) => {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ records }),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000)
    });
    await response.body?.cancel();
    if (!response.ok) throw new Error(`Audit sink rejected batch (${response.status})`);
  };
}
