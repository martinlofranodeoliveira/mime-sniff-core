# Contract — mime-sniff-core

Pure ESM in `src/sniff.mjs`, zero runtime dependencies, Node >= 22.
Only the first 64 bytes are read; short input matches fewer rules.

| Export | Result |
| --- | --- |
| `MAX_SNIFF_BYTES` (64) | Read cap. |
| `SUPPORTED` | Frozen `[{ mime, ext }]` (12 types). |
| `sniff(Uint8Array)` | `{ mime, ext }` or `null` when unknown. Longest minimum-length wins. |
| `head(...bytes)` | Test/demo helper building a `Uint8Array`. |

Covered: PNG, JPEG, GIF87a/89a, WebP (RIFF….WEBP), BMP, PDF, ZIP
(local-file header), gzip, 7z, SQLite3, MP3 (ID3 or frame sync), Ogg.
Unknown input returns `null` — never guessed. Only error: `NOT_BYTES`.
