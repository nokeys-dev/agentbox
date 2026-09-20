// Deterministic mulberry32 PRNG used by the fuzz suite so that a given
// FUZZ_SEED always reproduces the exact same sequence of generated inputs.
export function prng(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    int: (max) => Math.floor(next() * max),
    pick: (array) => array[Math.floor(next() * array.length)],
    chance: (p) => next() < p,
    bytes: (n) => Buffer.from(Array.from({ length: n }, () => Math.floor(next() * 256)))
  };
}
