# mime-sniff-core

File-type sniffing from leading magic bytes: exact rules, longest-match
wins, unknown returns null. Zero runtime dependencies, Node >= 22.

Part of the LOFRANO TECNOLOGIA open-source lab. MIT.

```js
import { sniff } from './src/sniff.mjs';
sniff(bytes); // { mime: 'image/png', ext: 'png' } or null
```

```sh
npm test          # 5 tests, node:test, no dependencies
npm run demo
```

12 types; only the first 64 bytes read. MIT — see `LICENSE`.
[Versão em português](README.pt-BR.md).
