import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sniff, head, SUPPORTED, MimeError } from '../src/sniff.mjs';

describe('known headers', () => {
  it('detects images', () => {
    assert.deepEqual(sniff(head(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)), { mime: 'image/png', ext: 'png' });
    assert.deepEqual(sniff(head(0xff, 0xd8, 0xff, 0xe0)), { mime: 'image/jpeg', ext: 'jpg' });
    assert.deepEqual(sniff(head(0x47, 0x49, 0x46, 0x38, 0x39, 0x61)), { mime: 'image/gif', ext: 'gif' });
    assert.deepEqual(sniff(head(0x42, 0x4d, 0x36)), { mime: 'image/bmp', ext: 'bmp' });
  });
  it('detects RIFF-WEBP by offset rule', () => {
    assert.deepEqual(
      sniff(head(0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50)),
      { mime: 'image/webp', ext: 'webp' },
    );
  });
  it('detects documents, archives and audio', () => {
    assert.deepEqual(sniff(head(0x25, 0x50, 0x44, 0x46, 0x2d)), { mime: 'application/pdf', ext: 'pdf' });
    assert.deepEqual(sniff(head(0x50, 0x4b, 0x03, 0x04)), { mime: 'application/zip', ext: 'zip' });
    assert.deepEqual(sniff(head(0x1f, 0x8b, 0x08)), { mime: 'application/gzip', ext: 'gz' });
    assert.deepEqual(sniff(head(0x49, 0x44, 0x33)), { mime: 'audio/mpeg', ext: 'mp3' });
    assert.deepEqual(sniff(head(0xff, 0xfb, 0x90)), { mime: 'audio/mpeg', ext: 'mp3' });
    assert.deepEqual(sniff(head(0x4f, 0x67, 0x67, 0x53)), { mime: 'audio/ogg', ext: 'ogg' });
  });
});

describe('unknown and bounds', () => {
  it('returns null instead of guessing', () => {
    assert.equal(sniff(head(0x00, 0x01, 0x02)), null);
    assert.equal(sniff(head(0x50, 0x4b)), null); // truncated ZIP
    assert.equal(sniff(new Uint8Array(0)), null);
    assert.equal(SUPPORTED.length >= 10, true);
  });
  it('rejects non-bytes', () => {
    assert.throws(() => sniff('PNG'), (e) => e.code === 'NOT_BYTES');
    assert.ok(new MimeError('X') instanceof Error);
  });
});
