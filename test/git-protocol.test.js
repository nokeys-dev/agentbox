import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePush, parsePushRequest, validateRef } from '../src/git-protocol.js';
import { packet, pushBody } from './support/fixture.js';

const zero = '0'.repeat(40);
const one = '1'.repeat(40);
const two = '2'.repeat(40);

test('parses all ref updates and separates create, update and delete', () => {
  const body = Buffer.concat([
    packet(`${zero} ${one} refs/heads/agent/new\0report-status-v2 side-band-64k agent=git/2.48.1\n`),
    packet(`${one} ${two} refs/heads/main\n`),
    packet(`${one} ${zero} refs/tags/old`), Buffer.from('0000PACKopaque data')
  ]);
  assert.deepEqual(parsePush(body).map((change) => change.operation), ['create', 'update', 'delete']);
});

test('rejects malformed packets, hidden commands and unsupported protocol extensions', () => {
  const invalid = [
    Buffer.from(''), Buffer.from('0000'), Buffer.from('zzzz'), Buffer.from('ffffshort'), Buffer.from('0001'),
    packet(`${one} ${two} refs/heads/main`),
    pushBody('refs/heads/../main'), pushBody('refs/heads/.hidden'), pushBody('refs/heads/main.lock'),
    pushBody('refs/heads/name\t'), pushBody('refs/heads/main', zero, zero),
    Buffer.concat([pushBody(), packet(`${one} ${two} refs/heads/hidden`)]),
    Buffer.concat([packet(`push-cert\0report-status`), Buffer.from('0000')]),
    Buffer.concat([packet(`shallow ${one}`), pushBody()]),
    Buffer.concat([packet(`${one} ${two} refs/heads/main\0push-options`), Buffer.from('0000')]),
    Buffer.concat([packet(`${one} ${two} refs/heads/main`), pushBody()]),
    Buffer.concat([packet(`${one} ${two} refs/heads/first`), pushBody('refs/heads/second')])
  ];
  for (const body of invalid) assert.throws(() => parsePush(body), { code: 'INVALID_PUSH' });
});

test('Unicode refs require opt-in and reject spoofing characters', () => {
  assert.throws(() => validateRef('refs/heads/agent/café'), { code: 'INVALID_PUSH' });
  assert.doesNotThrow(() => validateRef('refs/heads/agent/café', { allowUnicode: true }));
  // Spelled with String.fromCodePoint rather than embedded literally: several of these are
  // invisible or bidi-reordering characters, and this file should stay reviewable by eye rather
  // than silently containing the very characters it is testing the rejection of.
  const cp = (point) => String.fromCodePoint(point);
  const spoofed = [
    `refs/heads/agent/cafe${cp(0x0301)}`, // NFD: 'e' + combining acute accent -- not NFC-normalized
    `refs/heads/agent/a${cp(0x202e)}b`, // RIGHT-TO-LEFT OVERRIDE
    `refs/heads/agent/a${cp(0x200b)}b`, // ZERO WIDTH SPACE
    `refs/heads/agent/a${cp(0x00a0)}b`, // NO-BREAK SPACE
    `refs/heads/agent/a${cp(0x0085)}b` // NEL (a C1 control)
  ];
  for (const ref of spoofed) assert.throws(() => validateRef(ref, { allowUnicode: true }), { code: 'INVALID_PUSH' }, JSON.stringify(ref));
});

test('Unicode refs reject default-ignorable, private-use, unassigned, lookalike, and leading-combining-mark characters', () => {
  const cp = (...points) => String.fromCodePoint(...points);
  // One representative per rejected class -- see the property-escape comment on
  // `forbiddenCategory` in src/git-protocol.js for why each class is rejected.
  const table = [
    ['SOFT HYPHEN (Default_Ignorable + Cf)', `refs/heads/agent/a${cp(0x00ad)}b`],
    ['COMBINING GRAPHEME JOINER (Default_Ignorable, mid-segment)', `refs/heads/agent/a${cp(0x034f)}b`],
    ['MONGOLIAN VOWEL SEPARATOR (Default_Ignorable + Cf)', `refs/heads/agent/a${cp(0x180e)}b`],
    ['KHMER VOWEL INHERENT AQ (Default_Ignorable, mid-segment)', `refs/heads/agent/a${cp(0x17b4)}b`],
    ['VARIATION SELECTOR-16 (Default_Ignorable, mid-segment)', `refs/heads/agent/a${cp(0xfe0f)}b`],
    ['TAG LATIN SMALL LETTER A (Default_Ignorable + Cf, tag block)', `refs/heads/agent/a${cp(0xe0061)}b`],
    ['HANGUL CHOSEONG FILLER (Default_Ignorable, category Lo -- not Cf)', `refs/heads/agent/a${cp(0x115f)}b`],
    ['HANGUL JUNGSEONG FILLER (Default_Ignorable, category Lo)', `refs/heads/agent/a${cp(0x1160)}b`],
    ['HANGUL FILLER (Default_Ignorable, category Lo)', `refs/heads/agent/a${cp(0x3164)}b`],
    ['HALFWIDTH HANGUL FILLER (Default_Ignorable, category Lo)', `refs/heads/agent/a${cp(0xffa0)}b`],
    ['unassigned code point U+0378 (Cn)', `refs/heads/agent/a${cp(0x0378)}b`],
    ['private-use character U+E000 (Co)', `refs/heads/agent/a${cp(0xe000)}b`],
    ['Fullwidth Latin small letter a (Halfwidth/Fullwidth Forms block)', `refs/heads/agent/${cp(0xff41)}gent`],
    ['DIVISION SLASH', `refs/heads${cp(0x2215)}agent`],
    ['FRACTION SLASH', `refs/heads${cp(0x2044)}agent`],
    ['BIG SOLIDUS', `refs/heads${cp(0x29f8)}agent`],
    ['FULLWIDTH SOLIDUS', `refs/heads${cp(0xff0f)}agent`],
    ['combining mark at the start of a path segment', `refs/heads/agent/${cp(0x1d17b)}main`]
  ];
  for (const [label, ref] of table) assert.throws(() => validateRef(ref, { allowUnicode: true }), { code: 'INVALID_PUSH' }, label);
  // The same combining mark is fine attached to a base character in the middle of a segment --
  // only a *leading* combining mark (nothing to attach to) is rejected.
  assert.doesNotThrow(() => validateRef(`refs/heads/agent/a${cp(0x1d17b)}b`, { allowUnicode: true }));
});

test('a UTF-8 BOM at the start of a command is preserved (not silently stripped) and fails validation', () => {
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const command = Buffer.concat([bom, Buffer.from(`${one} ${two} refs/heads/main\0report-status`)]);
  const body = Buffer.concat([packet(command), Buffer.from('0000')]);
  // Both an ASCII-only repository (the default) and one with allowUnicode enabled must reject
  // this: if the BOM were silently stripped by decoding, the command would parse as an ordinary
  // ASCII update while the raw forwarded bytes still carried the BOM prefix -- a mismatch
  // between what was validated and what was actually sent upstream.
  assert.throws(() => parsePushRequest(body), { code: 'INVALID_PUSH' });
  assert.throws(() => parsePushRequest(body, { allowUnicode: true }), { code: 'INVALID_PUSH' });
});
