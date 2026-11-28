/**
 * Copies the shared SHA-3 implementation in packages/sha3/src into the
 * packages which use it.
 *
 * packages/sha3 is not published by itself, and a package on JSR or npm
 * cannot import a file outside its own directory, so each package gets a copy
 * of the files it needs under its src/sha3/. The copies are not tracked by
 * Git: packages/sha3 is the only place to edit, and the tasks which need the
 * copies (test, dnt, ...) run this script first.
 *
 * Usage (from anywhere in the repository):
 *   deno task sync:sha3
 *
 * It fails, without changing anything, if a target directory has a file or a
 * directory which this script did not generate.
 *
 * The tasks of several packages may run this at the same time, so the whole
 * run is serialized with a lock file, and each copy is replaced atomically:
 * neither another run of this script nor a compiler sees a half-written file.
 */

// The paths below are relative to the repository root.
Deno.chdir(new URL("..", import.meta.url));

// Held until the process exits.
const lock = Deno.openSync("packages/sha3/.sync.lock", {
  create: true,
  write: true,
});
lock.lockSync(true);

const SOURCE_DIR = "packages/sha3/src";

/** The files each package needs. */
const TARGETS: Record<string, string[]> = {
  // The permutation, and the hash functions which the package exports.
  "packages/mlkem/src/sha3": ["keccak.ts", "sha3.ts", "utils.ts"],
  // Only the permutation and the sponge.
  "packages/mldsa/src/sha3": ["keccak.ts"],
  // The permutation, and the hash functions which the tests use.
  "packages/hqc/src/sha3": ["keccak.ts", "sha3.ts", "utils.ts"],
};

/** The first line of the copy generated from the source file `name`. */
const headerLine = (name: string): string =>
  `// This file is generated from ${SOURCE_DIR}/${name} by "deno task sync:sha3".`;

// A checkout may have CRLF line endings (core.autocrlf), which must not make
// a copy look different.
const normalize = (text: string): string => text.replaceAll("\r\n", "\n");

function generate(name: string): string {
  const source = normalize(Deno.readTextFileSync(`${SOURCE_DIR}/${name}`));
  return `${headerLine(name)}\n// Do not edit it here.\n\n` + source;
}

function readOrUndefined(path: string): string | undefined {
  try {
    return normalize(Deno.readTextFileSync(path));
  } catch (e: unknown) {
    if (e instanceof Deno.errors.NotFound) return undefined;
    throw e;
  }
}

/**
 * Whether something other than a regular file is at `path`: a directory, or
 * a link, which reading and writing would follow to a file elsewhere.
 */
function isNotRegularFile(path: string): boolean {
  try {
    return !Deno.lstatSync(path).isFile;
  } catch (e: unknown) {
    if (e instanceof Deno.errors.NotFound) return false;
    throw e;
  }
}

function listDir(dir: string): Deno.DirEntry[] {
  try {
    return [...Deno.readDirSync(dir)];
  } catch (e: unknown) {
    if (e instanceof Deno.errors.NotFound) return [];
    throw e;
  }
}

/**
 * Whether the content is a copy which this script generated earlier for the
 * file name `name`. The header has to name the same file: a backup of a
 * generated file under another name (e.g. keccak.ts.bak) is not one.
 */
function isGeneratedFor(name: string, content: string): boolean {
  return content.startsWith(`${headerLine(name)}\n`);
}

// Generated copies which are not needed any more, to be removed.
const obsolete: string[] = [];
// Anything else in a target directory, including a file with the name of a
// copy but without its header. It is never removed or overwritten: it may be
// someone's work in progress.
const unknown: string[] = [];
const updates: [path: string, content: string][] = [];

// A copy is written under this name first, and then renamed.
const TEMP_PREFIX = ".sync-sha3-";

const tempName = (name: string): string => `${TEMP_PREFIX}${name}`;
// Leftovers of a run which was killed while writing, to be removed. Only the
// exact names which this script writes: .sync-sha3-keccak.ts.bak is not one.
const leftovers: string[] = [];

for (const [dir, names] of Object.entries(TARGETS)) {
  for (const name of names) {
    const path = `${dir}/${name}`;
    if (isNotRegularFile(path)) {
      unknown.push(path);
      continue;
    }
    const expected = generate(name);
    const current = readOrUndefined(path);
    if (current === expected) continue;
    // An existing file without the header was written by hand: it is not
    // overwritten.
    if (current !== undefined && !isGeneratedFor(name, current)) {
      unknown.push(path);
      continue;
    }
    updates.push([path, expected]);
  }
  for (const entry of listDir(dir)) {
    if (names.includes(entry.name)) continue;
    const path = `${dir}/${entry.name}`;
    if (entry.isFile && names.some((name) => tempName(name) === entry.name)) {
      leftovers.push(path);
    } else if (
      entry.isFile && isGeneratedFor(entry.name, readOrUndefined(path) ?? "")
    ) {
      obsolete.push(path);
    } else {
      unknown.push(path);
    }
  }
}

if (unknown.length > 0) {
  console.error(
    "Not generated from packages/sha3, so left as they are. Move or remove " +
      "them by hand:",
  );
  for (const path of unknown) console.error(`  ${path}`);
  Deno.exit(1);
}

// Progress goes to stderr: stdout belongs to the command which follows this
// script in a task (e.g. `deno bench --json`).
for (const path of leftovers) {
  Deno.removeSync(path);
}
for (const dir of Object.keys(TARGETS)) {
  Deno.mkdirSync(dir, { recursive: true });
}
for (const [path, content] of updates) {
  const slash = path.lastIndexOf("/");
  const temp = `${path.slice(0, slash)}/${tempName(path.slice(slash + 1))}`;
  Deno.writeTextFileSync(temp, content);
  Deno.renameSync(temp, path);
  console.error(`updated ${path}`);
}
for (const path of obsolete) {
  Deno.removeSync(path);
  console.error(`removed ${path}`);
}
