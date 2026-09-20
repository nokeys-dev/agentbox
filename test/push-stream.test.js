import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { Readable } from 'node:stream';
import { join } from 'node:path';
import { commandSectionEnd, createCommandSectionScanner, parsePushRequest } from '../src/git-protocol.js';
import { readPush } from '../src/push-stream.js';
import { fixture, packet, pushBody } from './support/fixture.js';

const oid = (c) => c.repeat(40);

test('commandSectionEnd waits for the flush and includes push options when negotiated', () => {
  const commands = packet(`${oid('1')} ${oid('2')} refs/heads/agent/x\0report-status push-options`);
  const withOptions = Buffer.concat([commands, Buffer.from('0000'), packet('ci.skip'), Buffer.from('0000'), Buffer.from('PACK')]);
  assert.equal(commandSectionEnd(withOptions.subarray(0, commands.length)), -1);
  assert.equal(commandSectionEnd(withOptions.subarray(0, commands.length + 4)), -1);
  assert.equal(commandSectionEnd(withOptions), withOptions.length - 4);
  assert.deepEqual(parsePushRequest(withOptions.subarray(0, withOptions.length - 4)).pushOptions, ['ci.skip']);
  assert.throws(() => commandSectionEnd(Buffer.from('zzzz')), { code: 'INVALID_PUSH' });
});

// A client pushing from a shallow clone sends its "shallow <sha1>" lines before the ref-update
// command that actually carries the capability list. A prior version of the scanner sniffed
// capabilities off the very first packet (the shallow line, which has none) and so mistook the
// command-list flush for the end of the whole section, silently dropping the options section.
// This reuses one scanner instance across a growing buffer (as push-stream.js does) with a chunk
// boundary landing at every offset inside the options section, to exercise the resumable path.
test('commandSectionEnd locates the options section past shallow lines, resuming correctly across a chunk split inside it', () => {
  const one = oid('1');
  const shallowPacket = packet(`shallow ${one}`);
  const command = packet(`${oid('2')} ${oid('3')} refs/heads/agent/x\0report-status push-options`);
  const optionsSection = Buffer.concat([packet('ci.skip'), packet('merge_request.x')]);
  const whole = Buffer.concat([shallowPacket, command, Buffer.from('0000'), optionsSection, Buffer.from('0000'), Buffer.from('PACK')]);
  const commandListFlushEnd = shallowPacket.length + command.length + 4;

  for (let split = commandListFlushEnd; split <= commandListFlushEnd + optionsSection.length; split++) {
    const scan = createCommandSectionScanner();
    assert.equal(scan(whole.subarray(0, split)), -1, `split at ${split}`);
    assert.equal(scan(whole), whole.length - 4, `split at ${split}`);
  }
  const parsed = parsePushRequest(whole.subarray(0, whole.length - 4));
  assert.deepEqual(parsed.shallow, [one]);
  assert.deepEqual(parsed.pushOptions, ['ci.skip', 'merge_request.x']);
});

test('readPush decides from the head and streams the remainder under a byte cap', async () => {
  const head = Buffer.concat([packet(`${oid('1')} ${oid('2')} refs/heads/agent/x\0report-status`), Buffer.from('0000')]);
  const pack = Buffer.concat([Buffer.from('PACK'), randomBytes(200_000)]);
  const chunks = [head.subarray(0, 10), head.subarray(10), pack.subarray(0, 50_000), pack.subarray(50_000)];
  const request = Object.assign(Readable.from(chunks), { headers: {} });
  const result = await readPush(request, { maxBodyBytes: 1024 * 1024 });
  assert.equal(result.changes[0].ref, 'refs/heads/agent/x');
  const forwarded = [];
  for await (const chunk of result.body) forwarded.push(chunk);
  assert.deepEqual(Buffer.concat(forwarded), Buffer.concat([head, pack]));

  const big = Object.assign(Readable.from([head, pack]), { headers: {} });
  const limited = await readPush(big, { maxBodyBytes: 100_000 });
  await assert.rejects((async () => { for await (const chunk of limited.body) void chunk; })(), { code: 'BODY_TOO_LARGE' });
  const noFlush = Object.assign(Readable.from([Buffer.from('0032'), randomBytes(2_000_000)]), { headers: {} });
  await assert.rejects(readPush(noFlush, { maxCommandBytes: 1024, maxBodyBytes: 4_000_000 }), { code: 'INVALID_PUSH' });
});

test('real Git pushes larger than the old buffer stream through; oversized pushes do not update refs', async (t) => {
  const f = await fixture({ maxBodyBytes: 3 * 1024 * 1024 });
  t.after(() => f.close());
  const clone = join(f.directory, 'large');
  await f.git(f.directory, 'clone', f.remote, clone);
  await f.git(clone, 'config', 'user.name', 'T');
  await f.git(clone, 'config', 'user.email', 't@example.com');
  await f.git(clone, 'switch', '-c', 'agent/large');
  await writeFile(join(clone, 'ok.bin'), randomBytes(2 * 1024 * 1024));
  await f.git(clone, 'add', '.');
  await f.git(clone, 'commit', '-m', 'two MiB');
  await f.git(clone, 'push', 'origin', 'HEAD:refs/heads/agent/large');
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/agent/large'), await f.git(clone, 'rev-parse', 'HEAD'));
  assert(f.calls.some((call) => call.streamed), 'provider received a stream, not a buffer');
  await writeFile(join(clone, 'too-big.bin'), randomBytes(4 * 1024 * 1024));
  await f.git(clone, 'add', '.');
  await f.git(clone, 'commit', '-m', 'four MiB');
  const before = await f.git(f.bare, 'rev-parse', 'refs/heads/agent/large');
  await assert.rejects(f.git(clone, 'push', 'origin', 'HEAD:refs/heads/agent/large'));
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/agent/large'), before);
});

test('a chunk boundary inside the PACK signature does not reject a valid push', async () => {
  const head = Buffer.concat([packet(`${oid('1')} ${oid('2')} refs/heads/agent/x\0report-status`), Buffer.from('0000')]);
  const whole = Buffer.concat([head, Buffer.from('PACK'), randomBytes(1000)]);
  for (let split = head.length; split <= head.length + 4; split++) {
    const request = Object.assign(Readable.from([whole.subarray(0, split), whole.subarray(split)]), { headers: {} });
    const result = await readPush(request, { maxBodyBytes: 1024 * 1024 });
    assert.equal(result.changes.length, 1, `split at ${split}`);
    const forwarded = [];
    for await (const chunk of result.body) forwarded.push(chunk);
    assert.deepEqual(Buffer.concat(forwarded), whole);
  }
  // Byte-at-a-time delivery of the head and signature also works.
  const bytes = [...whole.subarray(0, head.length + 4)].map((byte) => Buffer.from([byte]));
  const single = await readPush(Object.assign(Readable.from([...bytes, whole.subarray(head.length + 4)]), { headers: {} }), { maxBodyBytes: 1024 * 1024 });
  assert.equal(single.changes[0].ref, 'refs/heads/agent/x');
});

test('a command section trickled in tiny chunks is rejected in linear time', async () => {
  const maxCommandBytes = 1024 * 1024;
  // 16-byte chunks of complete 5-byte packets with no flush. Re-concatenating and re-parsing the
  // whole head per chunk would copy tens of GiB here; the incremental reader copies ~2 MiB.
  const stream = Buffer.alloc(maxCommandBytes + 64, '0005a');
  const chunks = [];
  for (let at = 0; at < stream.length; at += 16) chunks.push(stream.subarray(at, at + 16));
  const request = Object.assign(Readable.from(chunks), { headers: {} });
  const started = performance.now();
  await assert.rejects(readPush(request, { maxCommandBytes, maxBodyBytes: 8 * maxCommandBytes }), { code: 'INVALID_PUSH' });
  assert(performance.now() - started < 5_000, `took ${performance.now() - started} ms`);
});

test('probe detection only accepts a lone flush packet', async () => {
  const read = (chunks) => readPush(Object.assign(Readable.from(chunks), { headers: {} }), { maxBodyBytes: 1024 * 1024 });
  assert.equal((await read([Buffer.from('00'), Buffer.from('00')])).probe, true);
  await assert.rejects(read([Buffer.from('0000PACKxxxx')]), { code: 'INVALID_PUSH' });
  await assert.rejects(read([Buffer.from('0000'), Buffer.from('PACKxxxx')]), { code: 'INVALID_PUSH' });
});

function rawPush(f, { chunks, stallAfter = false }) {
  const url = new URL(`${f.remote}/git-receive-pack`);
  return new Promise((resolve) => {
    const req = httpRequest(url, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request', 'transfer-encoding': 'chunked' } });
    const result = { status: undefined, body: '', closed: false };
    req.on('response', (response) => {
      result.status = response.statusCode;
      response.setEncoding('utf8');
      response.on('data', (chunk) => { result.body += chunk; });
      response.on('end', () => resolve(result));
      response.on('error', () => resolve(result));
    });
    req.on('error', () => { result.closed = true; resolve(result); });
    req.on('close', () => { result.closed = true; if (result.status === undefined) resolve(result); });
    (async () => {
      for (const chunk of chunks) {
        if (req.destroyed) return;
        if (!req.write(chunk)) await new Promise((next) => { req.once('drain', next); req.once('close', next); });
      }
      if (!stallAfter && !req.destroyed) req.end();
    })();
  });
}

test('a denied push with a large pack is rejected without forwarding any bytes upstream', async (t) => {
  const f = await fixture({ maxBodyBytes: 64 * 1024 * 1024 });
  t.after(() => f.close());
  const pack = Buffer.concat([Buffer.from('PACK'), randomBytes(8 * 1024 * 1024)]);
  const chunks = [pushBody('refs/tags/v1'), ...Array.from({ length: 16 }, (_, index) => pack.subarray(index * 1024 * 1024, (index + 1) * 1024 * 1024))];
  const result = await rawPush(f, { chunks });
  assert.equal(result.status, 403);
  assert.match(result.body, /DENIED/);
  assert.equal(f.calls.filter((call) => !call.discovery).length, 0);
});

test('a client that stalls mid-body is disconnected by the inactivity bound', async (t) => {
  const f = await fixture({ bodyIdleTimeoutMs: 200 });
  t.after(() => f.close());
  const started = Date.now();
  const head = Buffer.concat([packet(`${oid('0')} ${oid('2')} refs/heads/agent/stall\0report-status`), Buffer.from('0000PACK')]);
  const result = await rawPush(f, { chunks: [head], stallAfter: true });
  assert(result.closed || result.status >= 400, 'stalled request was disconnected');
  assert(Date.now() - started < 10_000, 'disconnected promptly');
  await assert.rejects(f.git(f.bare, 'rev-parse', '--verify', 'refs/heads/agent/stall'));
});

test('probe requests are forwarded and audited as probes; flush-plus-data is never forwarded', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  for (const chunks of [[Buffer.from('0000PACKxxxx')], [Buffer.from('0000'), Buffer.from('more data')]]) {
    const result = await rawPush(f, { chunks });
    assert.equal(result.status, 400);
  }
  assert.equal(f.calls.filter((call) => !call.discovery).length, 0);
  const probe = await rawPush(f, { chunks: [Buffer.from('00'), Buffer.from('00')] });
  assert.equal(probe.status, 200);
  assert.equal(f.calls.filter((call) => !call.discovery).length, 1);
  const audit = readFileSync(join(f.directory, 'state', 'audit.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert(audit.some((record) => record.type === 'decision' && record.decision === 'allow' && record.probe === true));
});
