# AuthDiff / auth-tree-core

Ordered, typed comparison engine for normalized Soroban authorization trees.

```js
import { compareAuthorization, summarizeChanges } from '@authdiff/auth-tree-core';

const changes = compareAuthorization(before, after);
const { total, counts } = summarizeChanges(changes);
```

Each change carries a `kind` and an exact `path` into the authorization tree.
Paths use `[authorizationIndex, 'root', 'children', childIndex, 'args', argIndex]`.
The engine preserves entry and child order and reports:

| Kind | Meaning |
| --- | --- |
| `authorization-added` / `authorization-removed` | An entry appeared or disappeared |
| `principal-changed` | Same credential type, different principal |
| `credential-changed` | Same principal, different credential type |
| `call-added` / `call-removed` / `call-replaced` | A call appeared, disappeared or changed shape |
| `argument-changed` | An argument differs at its exact index |

Arguments are compared as opaque XDR strings. Changes to `i128` arguments also
include a lossless `decimal` field when the wire encoding is recognizable.

Input is bounded to 2048 nodes, depth 32, 128 arguments per invocation and
16384-character XDR strings. Invalid input throws instead of producing a
partial comparison.

Keep the five AuthDiff repositories as siblings. Run the review workbench with
`node backend/server.mjs` from their parent directory. Run `npm test` here for
the engine tests.
