import { GateError } from './errors.js';

const invalid = (message) => { throw new GateError(400, 'INVALID_PUSH', message); };
const zero = '0'.repeat(40);
// A ref name arrives as raw UTF-8 bytes inside a pkt-line. Buffer#toString('utf8') is lossy: any
// malformed byte sequence is silently replaced with U+FFFD instead of being rejected, which would
// let a client smuggle bytes that never round-trip to what the client actually sent. Decoding
// strictly (fatal: true) turns that into an explicit rejection instead. ignoreBOM: true is
// required too: TextDecoder's default (false) silently strips a leading EF BB BF from the decoded
// string, so a command whose raw bytes start with a BOM would be validated as if the BOM were not
// there while the unmodified raw bytes (BOM included) are exactly what still gets forwarded
// upstream -- a mismatch between what was validated and what was actually sent. With ignoreBOM
// true the BOM survives decoding as a literal U+FEFF character, which then fails to match the
// "<oldOid> <newOid> <ref>" command shape (or, inside an already-Unicode ref, is rejected as a
// forbidden format character), so the decoded string and the forwarded bytes never diverge.
const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
function decodeCommand(payload) {
  try { return strictUtf8Decoder.decode(payload); } catch { invalid('Invalid UTF-8 in ref update'); }
}
const supported = /^(report-status(?:-v2)?|side-band-64k|quiet|atomic|ofs-delta|delete-refs|push-options|object-format=sha1|agent=[!-~]+)$/;

function readPacket(buffer, offset) {
  if (offset + 4 > buffer.length) return undefined;
  const header = buffer.toString('latin1', offset, offset + 4);
  if (!/^[0-9a-f]{4}$/.test(header)) invalid('Invalid packet length');
  const length = Number.parseInt(header, 16);
  if (length === 0) return { flush: true, next: offset + 4 };
  if (length < 5 || length > 65520) invalid('Truncated or unsupported packet');
  if (offset + length > buffer.length) return undefined;
  return { flush: false, payload: buffer.subarray(offset + 4, offset + length), next: offset + length };
}

// Capabilities are always printable ASCII (parsePushRequest itself requires /^[\x20-\x7e]*$/ on
// this exact substring below), so decoding as latin1 is exact for the bytes that matter here and
// never risks a lossy multi-byte UTF-8 decode over the ref portion of the payload that precedes
// the NUL (which, for an allowUnicode repository, can legitimately contain multibyte UTF-8).
function capabilitiesOf(payload) {
  const text = payload.toString('latin1');
  const nul = text.indexOf('\0');
  return nul < 0 ? [] : text.slice(nul + 1).trim().split(/ +/).filter(Boolean);
}

// A client pushing from a shallow clone sends its "shallow <sha1>" lines before the ref-update
// commands; those lines never carry the NUL-separated capability list, so they must be skipped
// when hunting for the packet that does (see the comment on `first` below).
const shallowLine = /^shallow [0-9a-f]{40}\n?$/;

// Returns a resumable scanner: each call continues from the last complete packet, so feeding a
// growing buffer costs linear time overall. It returns the offset just past the command section
// (and the push-options section when negotiated), or -1 when more bytes are needed. Throws
// INVALID_PUSH on malformed pkt-lines.
export function createCommandSectionScanner() {
  let offset = 0;
  // The capability list rides on the first actual ref-update command, not on any "shallow" line
  // that precedes it, so `first` must skip those before latching onto a payload to sniff.
  let first;
  let options = false;
  let result = -1;
  return (buffer) => {
    while (result < 0) {
      const packet = readPacket(buffer, offset);
      if (!packet) return -1;
      offset = packet.next;
      if (!packet.flush) {
        if (!options && first === undefined) {
          const text = packet.payload.toString('latin1');
          if (!shallowLine.test(text)) first = text;
        }
        continue;
      }
      if (!options && first !== undefined && capabilitiesOf(Buffer.from(first, 'latin1')).includes('push-options')) options = true;
      else result = offset;
    }
    return result;
  };
}

export function commandSectionEnd(buffer) {
  return createCommandSectionScanner()(buffer);
}

export function parsePushRequest(head, { allowUnicode = false } = {}) {
  const changes = [];
  const shallow = [];
  const pushOptions = [];
  const seen = new Set();
  let capabilities = [];
  let offset = 0;
  for (;;) {
    const packet = readPacket(head, offset);
    if (!packet) invalid('A nonempty command list and flush packet are required');
    offset = packet.next;
    if (packet.flush) break;
    let command = decodeCommand(packet.payload);
    if (command.endsWith('\n')) command = command.slice(0, -1);
    const shallowMatch = /^shallow ([0-9a-f]{40})$/.exec(command);
    if (shallowMatch) {
      if (changes.length) invalid('shallow lines must precede commands');
      shallow.push(shallowMatch[1]);
      continue;
    }
    if (command.startsWith('push-cert')) invalid('Signed pushes (push certificates) are not supported by GitHub');
    if (command.includes('\0')) {
      if (changes.length !== 0) invalid('Capabilities must occur on the first command');
      const parts = command.split('\0');
      if (parts.length !== 2 || !/^[\x20-\x7e]*$/.test(parts[1])) invalid('Invalid capabilities');
      capabilities = parts[1].trim().split(/ +/).filter(Boolean);
      if (capabilities.includes('object-format=sha256')) invalid('SHA-256 repositories are not supported by GitHub');
      if (capabilities.some((capability) => !supported.test(capability))) invalid('Unsupported push capability');
      command = parts[0];
    }
    const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) (refs\/\S+)$/u.exec(command);
    if (!match) invalid('Expected an unsigned SHA-1 ref update');
    const [, oldOid, newOid, ref] = match;
    validateRef(ref, { allowUnicode });
    if (oldOid === zero && newOid === zero) invalid('An update cannot have two zero object IDs');
    if (seen.has(ref)) invalid('Duplicate ref update');
    seen.add(ref);
    changes.push({ ref, oldOid, newOid, operation: newOid === zero ? 'delete' : oldOid === zero ? 'create' : 'update' });
    if (changes.length > 256) invalid('Too many ref updates (maximum 256)');
  }
  if (changes.length === 0) invalid('A nonempty command list and flush packet are required');
  if (capabilities.includes('push-options')) {
    for (;;) {
      const packet = readPacket(head, offset);
      if (!packet) invalid('Push options must end with a flush packet');
      offset = packet.next;
      if (packet.flush) break;
      const option = packet.payload.toString('utf8').replace(/\n$/, '');
      if (!/^[\x20-\x7e]{1,256}$/.test(option)) invalid('Invalid push option');
      pushOptions.push(option);
      if (pushOptions.length > 32) invalid('Too many push options');
    }
  }
  if (offset < head.length && head.toString('latin1', offset, offset + 4) !== 'PACK') invalid('Unexpected data after command list');
  return { changes, pushOptions, shallow, capabilities };
}

// Git's own ref length limit (used by check-ref-format and receive-pack) is 1024 bytes of the
// on-the-wire encoding, not 1024 UTF-16 code units: a ref carrying multibyte characters can be
// under the .length cap yet over the real byte cap, so the limit is measured in UTF-8 bytes.
const asciiRef = /^[!-~]+$/;
// Every property name below (Cc, Cf, Co, Cn, Z, Default_Ignorable_Code_Point) is ordinary ASCII
// text -- \p{...} property-escape syntax, not a \u code-point escape -- so this regex is safe to
// keep literal in source: nothing here is, or risks becoming, an embedded invisible character.
//   \p{Cc}                         C0/C1 control characters.
//   \p{Z}                          every Unicode whitespace/separator character.
//   \p{Cf}                         format characters: covers every bidi override/embedding
//                                  control (LRE/RLE/PDF/LRO/RLO/LRI/RLI/FSI/PDI, ALM, LRM/RLM)
//                                  and every zero-width joiner/space/word-joiner/BOM, since all
//                                  of those are format characters by Unicode's own definition.
//   \p{Co}                         private-use characters: rendering is undefined by Unicode and
//                                  entirely up to whichever font/consumer decides, so two
//                                  renderers can show the same ref differently.
//   \p{Cn}                         unassigned code points: covers every current and future
//                                  Unicode noncharacter (U+FDD0-FDEF, U+xFFFE/U+xFFFF in every
//                                  plane) plus any code point with no assigned meaning yet.
//   \p{Default_Ignorable_Code_Point} Unicode's own "invisible by design" set -- soft hyphen,
//                                  combining grapheme joiner, the Mongolian vowel separator,
//                                  variation selectors, tag characters, and the Hangul filler
//                                  characters (which are letters, category Lo, so \p{Cf} alone
//                                  does not catch them) all fall in this property.
const forbiddenCategory = /[\p{Cc}\p{Z}\p{Cf}\p{Co}\p{Cn}\p{Default_Ignorable_Code_Point}]/u;

// A combining mark (\p{M}) is legitimate in the middle of a segment, attached to the base
// character before it (e.g. a script whose accented forms have no single precomposed code
// point). At the *start* of a segment it has nothing to attach to, so it either renders
// attached to the preceding "/" or not at all -- either way the segment can display as
// something other than its actual bytes.
const combiningMarkAtStart = /^\p{M}/u;

// Checked by explicit numeric code point rather than written as literal characters or \u
// escapes in this file's source: embedding the very lookalike/invisible characters this
// function rejects would make this file itself unreviewable by eye (the "Trojan Source"
// problem), which is a bad look for the code that specifically defends against ref names doing
// exactly that.
function isForbiddenCodePoint(point) {
  if (point === 0xfffd) return true; // REPLACEMENT CHARACTER (category So; not covered above)
  if (point >= 0xff00 && point <= 0xffef) return true; // Halfwidth and Fullwidth Forms: ordinary
  // letter/digit/punctuation lookalikes (e.g. fullwidth "a"), not covered by any category above
  if (point === 0x2215 || point === 0x2044 || point === 0x29f8) return true; // slash lookalikes
  // (DIVISION SLASH, FRACTION SLASH, BIG SOLIDUS); FULLWIDTH SOLIDUS U+FF0F is already in the
  // Halfwidth/Fullwidth range above. Any of these could visually fake an extra "/" path
  // separator without actually being one, evading the path-segment checks below.
  return false;
}

function hasForbiddenCharacter(ref) {
  if (forbiddenCategory.test(ref)) return true;
  for (const character of ref) if (isForbiddenCodePoint(character.codePointAt(0))) return true;
  return ref.split('/').some((segment) => combiningMarkAtStart.test(segment));
}

export function validateRef(ref, { allowUnicode = false } = {}) {
  if (Buffer.byteLength(ref, 'utf8') > 1024 || /[~^:?*[\\]/.test(ref) || ref.includes('..') || ref.includes('@{') || ref.endsWith('.') || ref.endsWith('/') ||
    ref.split('/').some((part) => !part || part.startsWith('.') || part.endsWith('.lock'))) invalid('Invalid ref name');
  if (!asciiRef.test(ref)) {
    if (!allowUnicode) invalid('Non-ASCII ref names are disabled for this repository');
    if (ref.normalize('NFC') !== ref) invalid('Ref names must be NFC-normalized');
    if (hasForbiddenCharacter(ref)) invalid('Ref name contains control, spacing, bidirectional, invisible, or lookalike characters');
  }
}

// Renders every character of `ref` that is not a printable, unambiguous ASCII character as a
// `\uXXXX` (or `\u{X...}` for an astral code point) escape, leaving ordinary ASCII characters
// untouched. Returns undefined for an ASCII-only ref, since there is nothing extra to show.
// Used wherever a ref is displayed to a human reviewer (the approval web UI, Slack
// notifications) so the exact code points making up a non-ASCII ref are always visible
// alongside its literal rendering, rather than relying on the reviewer's terminal or browser
// font to distinguish a spoofing character from an ordinary one.
export function refCodePointEscape(ref) {
  if (typeof ref !== 'string') return undefined;
  let sawNonAscii = false;
  const escaped = [...ref].map((character) => {
    const point = character.codePointAt(0);
    if (point >= 0x20 && point <= 0x7e) return character;
    sawNonAscii = true;
    return point > 0xffff ? `\\u{${point.toString(16)}}` : `\\u${point.toString(16).padStart(4, '0')}`;
  }).join('');
  return sawNonAscii ? escaped : undefined;
}

// parsePush (below) has no repository context, so it cannot apply a per-repository push-option
// allowlist or decide policy on shallow ref updates; it stays a protocol-only parser and keeps
// rejecting both. The real push path (push-stream.js's readPush, used by server.js) has config
// available and accepts shallow lines and allowlisted push options there instead of here.
export function assertSupportedPush({ shallow, capabilities }) {
  if (shallow.length) invalid('Shallow pushes are not supported');
  if (capabilities.includes('push-options')) invalid('Push options are not supported');
}

// Pack integrity and object connectivity are validated by the upstream Git server. Used directly
// by the git-protocol/fuzz unit tests as a strict protocol-only parser; the broker's push path
// uses readPush (push-stream.js) instead, which decides shallow/push-options against config.
export function parsePush(body) {
  const request = parsePushRequest(body);
  assertSupportedPush(request);
  return request.changes;
}
