# sha3

The SHA-3 (Keccak) implementation shared by the packages of this repository. It
is based on [noble-hashes](https://github.com/paulmillr/noble-hashes).

This is **not a published package**. A package on JSR or npm cannot import a
file outside its own directory, so each package gets a copy of the files it
needs under its `src/sha3/`.

The copies are generated and **not tracked by Git** (see `.gitignore`). This
directory is the only place to edit. The tasks which need the copies (`test`,
`dnt`, ...) generate them first, both the ones of the repository root and the
ones of each package. To generate them by hand, e.g. right after cloning the
repository so that an editor resolves the imports:

```sh
deno task sync:sha3
```

Each package publishes its copies to JSR, though Git ignores them, with
`"!src/sha3/"` in `publish.exclude` of its `deno.json`. Without it,
`deno publish` fails rather than publishing a package without them.

| File            | Contents                                                                                                     | Copied to               |
| --------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------- |
| `src/keccak.ts` | The Keccak permutation and `KeccakCore`, a minimal sponge with no dependencies and no input validation.      | `mlkem`, `mldsa`, `hqc` |
| `src/sha3.ts`   | `Keccak`, the validating hash interface on `KeccakCore`, and the hash functions (`sha3_256`, `shake256`, …). | `mlkem`, `hqc`          |
| `src/utils.ts`  | Utilities for `sha3.ts`.                                                                                     | `mlkem`, `hqc`          |

The implementations of ML-KEM, ML-DSA and HQC use only `KeccakCore`, which keeps
their bundles small. `@webpqc/mlkem` also exports the hash functions of
`sha3.ts` for applications; a bundler drops them if an application does not use
them. `hqc` has `sha3.ts` only for its tests.

The tests are in
[packages/mlkem/test/hashes.test.ts](../mlkem/test/hashes.test.ts). The list of
the files each package gets is in
[scripts/sync_sha3.ts](../../scripts/sync_sha3.ts).
