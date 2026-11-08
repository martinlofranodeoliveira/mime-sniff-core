#!/usr/bin/env node
// Demo: fixed headers, asserts exact output. --assert exits non-zero on mismatch.
import { sniff } from '../src/sniff.mjs';

const CASES = [
  [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 'image/png'],
  [[0xff, 0xd8, 0xff, 0xe0], 'image/jpeg'],
  [[0x25, 0x50, 0x44, 0x46, 0x2d], 'application/pdf'],
  [[0x00, 0x01, 0x02], null],
];

let failed = 0;
for (const [bytes, expected] of CASES) {
  const r = sniff(Uint8Array.from(bytes));
  const pass = (r?.mime ?? null) === expected;
  if (!pass) failed++;
  console.log(`${pass ? 'PASS' : 'FAIL'} [${bytes.map((b) => b.toString(16)).join(' ')}] -> ${r?.mime ?? 'null'}`);
}
if (process.argv.includes('--assert') && failed > 0) process.exit(1);
if (failed > 0) process.exitCode = 1;
console.log(failed === 0 ? 'demo: all cases as expected' : `demo: ${failed} mismatch(es)`);
