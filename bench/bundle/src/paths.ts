import { join, resolve } from "node:path";

/** bench/bundle */
export const TOOL_ROOT: string = resolve(import.meta.dirname, "..");
/** Repository root */
export const REPO_ROOT: string = resolve(TOOL_ROOT, "../..");
/**
 * Parent of the output directories for the generated bundles. Each run
 * creates its own directory in it, so that concurrent runs do not interfere.
 */
export const DIST: string = join(TOOL_ROOT, "dist");
