import { build, emptyDir } from "dnt";

await emptyDir("./npm");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: "both",
  test: true,
  declaration: "inline",
  scriptModule: "umd",
  importMap: "./deno.json",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "crystals-kyber-js",
    version: Deno.args[0],
    description:
      "A CRYSTALS-KYBER implementation written in TypeScript for various JavaScript runtimes",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/crystals-kyber-js.git",
    },
    homepage: "https://github.com/dajiaji/crystals-kyber-js#readme",
    license: "MIT",
    module: "./esm/mod.js",
    main: "./script/mod.js",
    types: "./esm/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/mod.js",
        "require": "./script/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "crystals-kyber",
      "kyber",
      "kem",
      "security",
      "encryption",
      "pqc",
      "post-quantum",
    ],
    engines: {
      "node": ">=16.0.0",
    },
    author: "Ajitomi Daisuke",
    bugs: {
      url: "https://github.com/dajiaji/crystals-kyber-js/issues",
    },
  },
});

// post build steps
Deno.copyFileSync("LICENSE", "npm/LICENSE");
Deno.copyFileSync("README.md", "npm/README.md");
