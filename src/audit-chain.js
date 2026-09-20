import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const GENESIS = '0'.repeat(64);

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hashOf(body) {
  return createHash('sha256').update(body.prevHash).update(canonical(body)).digest('hex');
}

export function chainRecord(event, previous) {
  const body = { ...event, seq: previous.seq + 1, prevHash: previous.hash };
  return { ...body, hash: hashOf(body) };
}

export function verifyChain(lines, previous = { seq: 0, hash: GENESIS }) {
  let head = previous;
  let count = 0;
  for (const [index, line] of lines.entries()) {
    if (!line) continue;
    let record;
    try { record = JSON.parse(line); } catch { return { ok: false, line: index + 1, reason: 'invalid JSON' }; }
    const { hash, ...body } = record;
    if (body.seq !== head.seq + 1) return { ok: false, line: index + 1, reason: 'sequence gap' };
    if (body.prevHash !== head.hash) return { ok: false, line: index + 1, reason: 'broken link' };
    if (hash !== hashOf(body)) return { ok: false, line: index + 1, reason: 'hash mismatch' };
    head = { seq: body.seq, hash };
    count++;
  }
  return { ok: true, head, count };
}

const rotated = /^audit-(\d+)-(\d+)\.jsonl$/;

export function auditFiles(directory) {
  const names = readdirSync(directory).filter((name) => rotated.test(name)).sort((a, b) => {
    const [, am, an] = rotated.exec(a);
    const [, bm, bn] = rotated.exec(b);
    return Number(am) - Number(bm) || (BigInt(an) < BigInt(bn) ? -1 : BigInt(an) > BigInt(bn) ? 1 : 0);
  });
  const files = names.map((name) => join(directory, name));
  if (existsSync(join(directory, 'audit.jsonl'))) files.push(join(directory, 'audit.jsonl'));
  return files;
}

export function lastLine(path) {
  const fd = openSync(path, 'r');
  try {
    const size = fstatSync(fd).size;
    const length = Math.min(size, 1024 * 1024);
    const buffer = Buffer.alloc(length);
    readSync(fd, buffer, 0, length, size - length);
    const lines = buffer.toString('utf8').trimEnd().split('\n');
    return lines.at(-1);
  } finally { closeSync(fd); }
}

export function readChainHead(directory) {
  for (const file of auditFiles(directory).reverse()) {
    const line = lastLine(file);
    if (!line) continue;
    let record;
    try { record = JSON.parse(line); } catch { throw new Error('Audit chain tail is invalid; run npm run audit:verify'); }
    const { hash, ...body } = record;
    if (!Number.isSafeInteger(body.seq) || typeof hash !== 'string' || hash !== hashOf(body)) {
      throw new Error('Audit chain tail is invalid; run npm run audit:verify');
    }
    return { seq: body.seq, hash };
  }
  return { seq: 0, hash: GENESIS };
}
