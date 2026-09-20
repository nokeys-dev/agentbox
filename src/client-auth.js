import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { GateError, assert } from './errors.js';

const digest = (value) => createHash('sha256').update(value).digest();

export function loadClientToken(path) {
  assert((statSync(path).mode & 0o077) === 0, 'Client token file must be owner-only (chmod 600)');
  const token = readFileSync(path, 'utf8').trim();
  assert(/^[\x21-\x7e]{32,512}$/.test(token), 'Client token must be at least 32 printable characters');
  return token;
}

export function createClientAuth(token) {
  if (token === undefined) return () => {};
  assert(token !== '', 'createClientAuth requires a non-empty token, or undefined to disable authentication');
  const expected = digest(token);
  return (request) => {
    const header = request.headers.authorization ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
    // Compare fixed-length digests so neither length nor content leaks through timing.
    if (!presented || !timingSafeEqual(digest(presented), expected)) {
      throw new GateError(401, 'UNAUTHENTICATED', 'A valid workspace client token is required');
    }
  };
}

// Fleet mode: the bearer token is not compared to anything here; it is returned so the assertion
// verifier can check it against the assertion's cnf binding. Format-checked so garbage never
// reaches the hash, and the same UNAUTHENTICATED rejection as static mode when absent.
export function createAssertionBoundAuth() {
  return (request) => {
    const header = request.headers.authorization ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!/^[\x21-\x7e]{32,512}$/.test(presented)) throw new GateError(401, 'UNAUTHENTICATED', 'A valid workspace client token is required');
    return presented;
  };
}
