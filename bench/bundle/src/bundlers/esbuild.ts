/**
 * esbuild: `bundle`, `minify`, ESM.
 */

import * as esbuild from "esbuild";
import { dirname, resolve } from "node:path";

import { TOOL_ROOT } from "../paths.ts";
import {
  WEBPQC_SPECIFIER,
  webpqcEntryPath,
  webpqcPackageOf,
  webpqcSideEffects,
} from "../sources.ts";
import type { BundleOutput, Bundler } from "./types.ts";

export const TARGET = "es2022";

/**
 * Resolves `@webpqc/*` to the repository sources, applying each package's
 * npm `sideEffects` value to all of its modules.
 */
const webpqcSources: esbuild.Plugin = {
  name: "webpqc-sources",
  setup(build) {
    build.onResolve({ filter: WEBPQC_SPECIFIER }, (args) => {
      const name = args.path.slice("@webpqc/".length);
      return {
        path: webpqcEntryPath(name),
        sideEffects: webpqcSideEffects(name),
      };
    });
    // Relative imports inside packages/<name>/
    build.onResolve({ filter: /^\.\.?\// }, (args) => {
      const pkg = webpqcPackageOf(args.importer);
      if (pkg === undefined) return undefined;
      return {
        path: resolve(dirname(args.importer), args.path),
        sideEffects: webpqcSideEffects(pkg),
      };
    });
  },
};

function normalizeModulePath(path: string): string {
  return path.replace(/^(\.\.\/)+/, "").replace(/^.*node_modules\//, "");
}

export const esbuildBundler: Bundler = {
  id: "esbuild",
  description:
    `esbuild@${esbuild.version} (bundle, minify, format=esm, target=${TARGET})`,
  async bundle(source: string): Promise<BundleOutput> {
    const result = await esbuild.build({
      stdin: { contents: source, resolveDir: TOOL_ROOT, loader: "js" },
      bundle: true,
      format: "esm",
      platform: "neutral",
      mainFields: ["module", "main"],
      target: TARGET,
      minify: true,
      write: false,
      legalComments: "none",
      logLevel: "silent",
      metafile: true,
      plugins: [webpqcSources],
    });
    const [output] = Object.values(result.metafile.outputs);
    const modules = Object.fromEntries(
      Object.entries(output.inputs)
        .filter(([, v]) => v.bytesInOutput > 0)
        .sort((a, b) => b[1].bytesInOutput - a[1].bytesInOutput)
        .map(([path, v]) => [normalizeModulePath(path), v.bytesInOutput]),
    );
    return { code: result.outputFiles[0].contents, modules };
  },
};
