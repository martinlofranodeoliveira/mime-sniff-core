// SPDX-License-Identifier: MIT
// File-type sniffing from leading magic bytes: exact prefix/range rules,
// longest-match wins, unknown returns null (never guessed). No network,
// no I/O.

export const MAX_SNIFF_BYTES = 64;

export class MimeError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'MimeError';
    this.code = code;
  }
}

const B = (...nums) => Uint8Array.from(nums);

// [mime, ext, minLength, test(head: Uint8Array) -> boolean]
const RULES = Object.freeze([
  ['image/png', 'png', 8, (h) => h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47 && h[4] === 0x0d && h[5] === 0x0a && h[6] === 0x1a && h[7] === 0x0a],
  ['image/jpeg', 'jpg', 3, (h) => h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff],
  ['image/gif', 'gif', 6, (h) => h[0] === 0x47 && h[1] === 0x49 && h[2] === 0x46 && h[3] === 0x38 && (h[4] === 0x37 || h[4] === 0x39) && h[5] === 0x61],
  ['image/webp', 'webp', 12, (h) => h[0] === 0x52 && h[1] === 0x49 && h[2] === 0x46 && h[3] === 0x46 && h[8] === 0x57 && h[9] === 0x45 && h[10] === 0x42 && h[11] === 0x50],
  ['image/bmp', 'bmp', 2, (h) => h[0] === 0x42 && h[1] === 0x4d],
  ['application/pdf', 'pdf', 5, (h) => h[0] === 0x25 && h[1] === 0x50 && h[2] === 0x44 && h[3] === 0x46 && h[4] === 0x2d],
  ['application/zip', 'zip', 4, (h) => h[0] === 0x50 && h[1] === 0x4b && h[2] === 0x03 && h[3] === 0x04],
  ['application/gzip', 'gz', 2, (h) => h[0] === 0x1f && h[1] === 0x8b],
  ['application/x-7z-compressed', '7z', 6, (h) => h[0] === 0x37 && h[1] === 0x7a && h[2] === 0xbc && h[3] === 0xaf && h[4] === 0x27 && h[5] === 0x1c],
  ['application/x-sqlite3', 'sqlite', 16, (h) => h[0] === 0x53 && h[1] === 0x51 && h[2] === 0x4c && h[3] === 0x69 && h[4] === 0x74 && h[5] === 0x65 && h[6] === 0x20],
  ['audio/mpeg', 'mp3', 3, (h) => (h[0] === 0x49 && h[1] === 0x44 && h[2] === 0x33) || (h[0] === 0xff && (h[1] & 0xe0) === 0xe0)],
  ['audio/ogg', 'ogg', 4, (h) => h[0] === 0x4f && h[1] === 0x67 && h[2] === 0x67 && h[3] === 0x53],
]);

export const SUPPORTED = Object.freeze(RULES.map(([mime, ext]) => ({ mime, ext })));

/**
 * Sniff leading bytes -> { mime, ext } or null when unknown.
 * Only the first MAX_SNIFF_BYTES are read; short input simply matches less.
 */
export function sniff(input) {
  if (!(input instanceof Uint8Array)) throw new MimeError('NOT_BYTES');
  const head = input.slice(0, MAX_SNIFF_BYTES);
  let best = null;
  for (const [mime, ext, min, test] of RULES) {
    if (head.length < min) continue;
    let ok = false;
    try {
      ok = test(head);
    } catch {
      ok = false;
    }
    if (ok && (!best || min > best.min)) best = { mime, ext, min };
  }
  return best ? { mime: best.mime, ext: best.ext } : null;
}

/** Helper for tests/demos: build a head from byte lists. */
export function head(...nums) {
  return B(...nums);
}
