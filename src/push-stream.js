import { Readable } from 'node:stream';
import { GateError } from './errors.js';
import { createCommandSectionScanner, parsePushRequest } from './git-protocol.js';

const tooLarge = (maxBodyBytes) => new GateError(413, 'BODY_TOO_LARGE', `Request exceeds ${maxBodyBytes} bytes`);

// Buffers only the command section (bounded by maxCommandBytes), parses it so policy can decide
// before any byte goes upstream, then exposes the whole request (head first, then the pack) as a
// stream that errors once the total, command section included, exceeds maxBodyBytes.
export async function readPush(request, { maxCommandBytes = 1024 * 1024, maxBodyBytes, allowUnicode = false }) {
  if (request.headers['content-encoding'] && request.headers['content-encoding'] !== 'identity') {
    throw new GateError(415, 'ENCODING_UNSUPPORTED', 'Compressed request bodies are not supported');
  }
  if (Number(request.headers['content-length']) > maxBodyBytes) throw tooLarge(maxBodyBytes);
  const iterator = request[Symbol.asyncIterator]();
  // Amortized-doubling buffer plus a resumable scanner keep head buffering linear in its size,
  // even when a client sends the command section one byte at a time.
  let storage = Buffer.allocUnsafe(4096);
  let length = 0;
  let done = false;
  const append = (chunk) => {
    if (length + chunk.length > storage.length) {
      const grown = Buffer.allocUnsafe(Math.max(storage.length * 2, length + chunk.length));
      storage.copy(grown, 0, 0, length);
      storage = grown;
    }
    chunk.copy(storage, length);
    length += chunk.length;
  };
  const pull = async () => {
    const next = await iterator.next();
    if (next.done) done = true;
    else append(next.value);
  };
  const scan = createCommandSectionScanner();
  let end = -1;
  while (end < 0 && !done) {
    await pull();
    end = scan(storage.subarray(0, length));
    if (length > maxBodyBytes) throw tooLarge(maxBodyBytes);
    if (end < 0 && length > maxCommandBytes) throw new GateError(400, 'INVALID_PUSH', 'Command section exceeds limit or never ends');
  }
  // Wait until four bytes follow the section (or EOF) so a chunk boundary inside the PACK signature
  // cannot make a valid push look like trailing garbage, and so a lone flush is known to be alone.
  while (end >= 0 && length - end < 4 && !done) await pull();
  const buffered = Buffer.from(storage.subarray(0, length));
  // Git sends a lone flush packet as an authentication probe before a large chunked push. It
  // carries no ref updates, so it needs no policy decision. Anything after the flush is parsed
  // (and rejected) as an ordinary push below.
  if (done && length === 4 && buffered.toString('latin1') === '0000') {
    return { probe: true, changes: [], pushOptions: [], shallow: [], capabilities: [], body: buffered };
  }
  if (end < 0) end = length;
  // Unlike parsePush (git-protocol.js, used by the fuzz/unit tests as a protocol-only parser with
  // no repository context), a real push here is decided against config: shallow lines are accepted
  // unconditionally and push options are allowed or denied per repository (see server.js), so no
  // blanket assertSupportedPush() rejection applies on this path.
  const parsed = parsePushRequest(buffered.subarray(0, end + Math.min(4, length - end)), { allowUnicode });
  let total = length;
  async function* remainder() {
    // The bytes read past the section to check the PACK signature may already exceed the cap;
    // fail the stream before yielding anything so no byte of an oversized push goes upstream.
    if (total > maxBodyBytes) throw tooLarge(maxBodyBytes);
    yield buffered;
    if (done) return;
    for (;;) {
      const next = await iterator.next();
      if (next.done) return;
      total += next.value.length;
      if (total > maxBodyBytes) throw tooLarge(maxBodyBytes);
      yield next.value;
    }
  }
  return { ...parsed, body: Readable.from(remainder(), { objectMode: false }) };
}
