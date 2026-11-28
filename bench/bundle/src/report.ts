/**
 * Result types and output formatting (console table / Markdown).
 */

import type { BundlerId } from "./bundlers/index.ts";
import type { LibId, Role } from "./libs.ts";
import type { Sizes } from "./measure.ts";

export interface LibResult extends Sizes {
  /** Bytes in the minified output per source module (esbuild only). */
  modules?: Record<string, number>;
}

/**
 * A value for each library which implements the algorithm of a suite:
 * `@webpqc` always does.
 */
export type ByLib<T> = Record<"@webpqc", T> & Partial<Record<LibId, T>>;

export interface Result {
  id: string;
  label: string;
  role: Role;
  packages: ByLib<string[]>;
  sizes: Partial<Record<BundlerId, ByLib<LibResult>>>;
}

export interface Meta {
  revision: string;
  /** Whether the bundles were checked by running them against each other. */
  verified: boolean;
  bundlers: Partial<Record<BundlerId, string>>;
  nobleVersion: string;
  node: string;
}

/** Shown where `@noble/post-quantum` does not implement the algorithm. */
const NONE = "-";

const fmt = (n: number): string => n.toLocaleString("en-US");
const pkgs = (list: string[]): string =>
  list.map((p) => `\`${p}\``).join(" + ");
/** `a`, `a and b`, or `a, b and c`. */
const enumerate = (list: string[]): string =>
  list.length < 2
    ? list.join("")
    : `${list.slice(0, -1).join(", ")} and ${list.at(-1)}`;
const ratio = (s: ByLib<LibResult>, format: "gzip" | "brotli"): string => {
  const noble = s["@noble/post-quantum"];
  return noble === undefined
    ? NONE
    : (s["@webpqc"][format] / noble[format]).toFixed(2);
};

export function printTable(results: Result[], bundlers: BundlerId[]): void {
  for (const format of ["gzip", "brotli"] as const) {
    console.log(`\n${format}`);
    console.table(
      results.map((r) => {
        const row: Record<string, string | number> = {
          suite: r.id,
          role: r.role,
        };
        for (const b of bundlers) {
          const s = r.sizes[b]!;
          row[`${b} @webpqc`] = s["@webpqc"][format];
          row[`${b} noble`] = s["@noble/post-quantum"]?.[format] ?? NONE;
          row[`${b} ratio`] = ratio(s, format);
        }
        return row;
      }),
    );
  }
}

export function printModules(
  title: string,
  modules: Record<string, number>,
): void {
  console.log(`\n${title}`);
  for (const [path, bytes] of Object.entries(modules)) {
    console.log(`  ${String(bytes).padStart(7)}  ${path}`);
  }
}

export function toMarkdown(
  results: Result[],
  meta: Meta,
  bundlers: BundlerId[],
): string {
  const webpqcPackages = [
    ...new Set(results.flatMap((r) => r.packages["@webpqc"])),
  ].map((p) => `\`${p}\``);
  const webpqcOnly = results.some((r) =>
    r.packages["@noble/post-quantum"] === undefined
  );
  const lines = [
    "# Bundle size benchmark",
    "",
    `- @webpqc: ${
      enumerate(webpqcPackages)
    }, repository sources @ \`${meta.revision}\``,
    `- noble: \`@noble/post-quantum@${meta.nobleVersion}\``,
    "- `sideEffects: false` is honored for all packages on both sides",
    meta.verified
      ? "- bundles verified by cross-library key derivation, encap/decap and sign/verify"
      : "- **bundles NOT verified** (`--no-verify`)",
    "- sizes in bytes (min / gzip -9 / brotli -11); ratios = @webpqc / noble",
    ...(webpqcOnly
      ? [
        `- \`${NONE}\`: not implemented by noble${
          meta.verified
            ? "; the bundles of such an algorithm are verified within @webpqc only"
            : ""
        }`,
      ]
      : []),
    `- Node.js ${meta.node}`,
    "",
    "Bundlers:",
    "",
    ...bundlers.map((b) => `- **${b}**: ${meta.bundlers[b]}`),
  ];
  for (const b of bundlers) {
    lines.push("", `## ${b}`);
    for (const format of ["gzip", "brotli"] as const) {
      lines.push(
        "",
        `### ${format}`,
        "",
        `| Algorithm | Role | @webpqc package | @webpqc min | @webpqc ${format} | noble min | noble ${format} | ratio |`,
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
      );
      for (const r of results) {
        const s = r.sizes[b]!;
        const a = s["@webpqc"];
        const n = s["@noble/post-quantum"];
        lines.push(
          `| ${r.label} | ${r.role} | ${pkgs(r.packages["@webpqc"])} | ${
            fmt(a.min)
          } | ${fmt(a[format])} | ${n === undefined ? NONE : fmt(n.min)} | ${
            n === undefined ? NONE : fmt(n[format])
          } | ${ratio(s, format)} |`,
        );
      }
    }
  }
  lines.push("");
  return lines.join("\n");
}
