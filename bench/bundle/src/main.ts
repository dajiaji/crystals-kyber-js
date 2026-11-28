/**
 * Bundle size benchmark for `@webpqc/mlkem`, `@webpqc/mldsa` and
 * `@webpqc/hqc`.
 *
 * For each parameter set, bundles a minimal "typical" application per
 * operation (key generation, encap / decap, sign / verify) with real-world
 * bundlers (esbuild, rollup + terser) and reports the minified / gzip /
 * brotli sizes. `@noble/post-quantum` is measured the same way for
 * comparison, for the algorithms which it implements. `sideEffects: false` is
 * honored for every package on both sides.
 */

import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";

import { BUNDLERS } from "./bundlers/index.ts";
import type { BundlerId } from "./bundlers/index.ts";
import { libsOf, ROLES } from "./libs.ts";
import type { Role } from "./libs.ts";
import { measure } from "./measure.ts";
import { DIST, REPO_ROOT, TOOL_ROOT } from "./paths.ts";
import { printModules, printTable, toMarkdown } from "./report.ts";
import type { ByLib, LibResult, Meta, Result } from "./report.ts";
import { SUITES } from "./suites.ts";
import { verify } from "./verify.ts";
import type { BundleFiles } from "./verify.ts";

const USAGE = `Usage: node src/main.ts [options]

Options:
  --filter <substr>   Only run suites whose id contains <substr>
  --bundler <id>      Only use the given bundler (esbuild | rollup); repeatable
  --analyze           Print the per-module size breakdown (esbuild only)
  --json <path>       Write the results as JSON
  --md <path>         Write the results as Markdown tables
  --keep              Keep the generated bundles under ./dist/run-*
  --no-verify         Skip the runtime check of the bundles
  -h, --help          Show this help
`;

function gitRevision(): string {
  try {
    const git = (...args: string[]) =>
      execFileSync("git", args, { cwd: REPO_ROOT }).toString().trim();
    const rev = git("rev-parse", "--short", "HEAD");
    // Both the measured sources and this tool (incl. its lockfile) affect
    // the results.
    const dirty = git(
      "status",
      "--porcelain",
      "--",
      "packages",
      relative(REPO_ROOT, TOOL_ROOT),
    ).length > 0;
    return dirty ? `${rev}-dirty` : rev;
  } catch {
    return "unknown";
  }
}

async function packageVersion(name: string): Promise<string> {
  const path = join(TOOL_ROOT, "node_modules", name, "package.json");
  const pkg = JSON.parse(await readFile(path, "utf8")) as { version: string };
  return pkg.version;
}

async function main(): Promise<void> {
  const { values: opts } = parseArgs({
    options: {
      filter: { type: "string", default: "" },
      bundler: { type: "string", multiple: true },
      analyze: { type: "boolean", default: false },
      json: { type: "string" },
      md: { type: "string" },
      keep: { type: "boolean", default: false },
      verify: { type: "boolean", default: true },
      help: { type: "boolean", short: "h", default: false },
    },
    allowNegative: true,
    strict: true,
  });
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }

  const suites = SUITES.filter((s) => s.id.includes(opts.filter));
  if (suites.length === 0) {
    throw new Error(`No suite matches --filter ${opts.filter}`);
  }
  const bundlers = opts.bundler === undefined
    ? BUNDLERS
    : opts.bundler.map((id) => {
      const b = BUNDLERS.find((b) => b.id === id);
      if (b === undefined) throw new Error(`Unknown bundler: ${id}`);
      return b;
    });

  // Bundles are always written to disk (they are imported for verification),
  // into a directory of this run only: another run may be using ./dist at
  // the same time. It is removed afterwards unless --keep is given.
  await mkdir(DIST, { recursive: true });
  const outDir = await mkdtemp(join(DIST, "run-"));

  const results: Result[] = [];
  try {
    for (const suite of suites) {
      const roles: readonly Role[] = ROLES[suite.kind];
      const libs = libsOf(suite);
      const packages = Object.fromEntries(
        libs.map((lib) => [lib.id, lib.packages(suite)]),
      ) as ByLib<string[]>;
      const byRole = Object.fromEntries(
        roles.map((role) => [role, {}]),
      ) as Record<Role, Result["sizes"]>;

      for (const bundler of bundlers) {
        const files: BundleFiles = {};
        for (const role of roles) {
          byRole[role][bundler.id] = {} as ByLib<LibResult>;
        }
        for (const lib of libs) {
          const libFiles: Partial<Record<Role, string>> = {};
          files[lib.id] = libFiles;
          for (const role of roles) {
            const { code, modules } = await bundler.bundle(
              lib.entry(suite, role),
            );
            const file = join(
              outDir,
              bundler.id,
              `${suite.id}.${lib.id.replace(/[@/]/g, "")}.${role}.mjs`,
            );
            await mkdir(join(outDir, bundler.id), { recursive: true });
            await writeFile(file, code);
            libFiles[role] = file;
            byRole[role][bundler.id]![lib.id] = { ...measure(code), modules };
            if (opts.analyze && modules !== undefined) {
              printModules(
                `${suite.id} / ${bundler.id} / ${lib.id} / ${role}`,
                modules,
              );
            }
          }
        }
        if (opts.verify) {
          await verify(suite, files);
        }
        process.stderr.write(
          `  ${opts.verify ? "✔" : "-"} ${suite.id} (${bundler.id})\n`,
        );
      }

      for (const role of roles) {
        results.push({
          id: suite.id,
          label: suite.label,
          role,
          packages,
          sizes: byRole[role],
        });
      }
    }
  } finally {
    if (opts.keep) {
      process.stderr.write(
        `  bundles kept in ${relative(TOOL_ROOT, outDir)}\n`,
      );
    } else {
      // Only the directory of this run: ./dist itself stays, as another run
      // may be about to create its directory in it.
      await rm(outDir, { recursive: true, force: true });
    }
  }

  const bundlerIds: BundlerId[] = bundlers.map((b) => b.id);
  const meta: Meta = {
    revision: gitRevision(),
    verified: opts.verify,
    bundlers: Object.fromEntries(bundlers.map((b) => [b.id, b.description])),
    nobleVersion: await packageVersion("@noble/post-quantum"),
    node: process.version,
  };

  printTable(results, bundlerIds);

  if (opts.json !== undefined) {
    await writeFile(
      resolve(opts.json),
      JSON.stringify({ meta, results }, null, 2) + "\n",
    );
  }
  if (opts.md !== undefined) {
    await writeFile(
      resolve(opts.md),
      toMarkdown(results, meta, bundlerIds),
    );
  }
}

await main();
