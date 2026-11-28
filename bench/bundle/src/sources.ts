/**
 * Resolution of `@webpqc/*` packages to the repository sources.
 *
 * `@webpqc/*` packages are bundled directly from `packages/<name>/mod.ts` so
 * that the numbers always reflect the current working tree. To behave exactly
 * like the published npm packages, the `sideEffects` value that each package
 * declares in its npm `package.json` (configured in `packages/<name>/dnt.ts`)
 * is applied to every module of that package through each bundler's official
 * per-module side effects hook.
 *
 * Third-party dependencies (`@noble/post-quantum` and its dependencies) are
 * resolved from `node_modules` as usual, where each bundler reads their
 * `package.json` `sideEffects` field by itself.
 */

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { REPO_ROOT } from "./paths.ts";

const PACKAGES_DIR = join(REPO_ROOT, "packages");

/** Package entry points. */
export const WEBPQC_SPECIFIER: RegExp = /^@webpqc\/([a-z0-9-]+)$/;

/** Resolve a package to its repository source entry. */
export function webpqcEntryPath(name: string): string {
  return join(PACKAGES_DIR, name, "mod.ts");
}

/** Returns the package name if `path` is inside `packages/<name>/`. */
export function webpqcPackageOf(path: string): string | undefined {
  const rel = relative(PACKAGES_DIR, path);
  if (rel.startsWith("..") || rel === "") return undefined;
  return rel.split(sep)[0];
}

const sideEffectsCache = new Map<string, boolean>();

/**
 * The `sideEffects` value of the npm package built from `packages/<name>`,
 * read from its `dnt.ts`. Defaults to `true` (the npm default) if absent.
 */
export function webpqcSideEffects(name: string): boolean {
  let value = sideEffectsCache.get(name);
  if (value === undefined) {
    let src = "";
    try {
      src = readFileSync(join(PACKAGES_DIR, name, "dnt.ts"), "utf8");
    } catch {
      // no dnt.ts
    }
    value = /sideEffects:\s*false\b/.test(src) ? false : true;
    sideEffectsCache.set(name, value);
  }
  return value;
}
