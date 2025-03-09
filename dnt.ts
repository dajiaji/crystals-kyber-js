import { build, emptyDir } from "@deno/dnt";
import { copySync } from "@std/fs";

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.json"));

// pre build steps
await emptyDir(`./npm/${Deno.args[0]}`);
await emptyDir(`./npm/test/${Deno.args[0]}/runtimes/cloudflare`);
try {
  await Deno.remove("test/runtimes/browsers/node_modules", {
    recursive: true,
  });
} catch {
  // ignore
}
try {
  await Deno.remove("test/runtimes/bun/node_modules", {
    recursive: true,
  });
} catch {
  // ignore
}
try {
  await Deno.remove("test/runtimes/cloudflare/node_modules", {
    recursive: true,
  });
} catch {
  // ignore
}

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm/" + Deno.args[0],
  typeCheck: "both",
  test: true,
  declaration: "inline",
  scriptModule: "umd",
  importMap: "./npm/import_map.json",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  testPattern: "test/**/*.test.ts",
  package: {
    name: Deno.args[0],
    version: denoPkg.version,
    description:
      "An ML-KEM/CRYSTALS-KYBER implementation written in TypeScript for various JavaScript runtimes",
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
      "ml-kem",
      "mlkem",
      "fips203",
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
copySync(
  "test/runtimes/cloudflare",
  `npm/test/${Deno.args[0]}/runtimes/cloudflare`,
  { overwrite: true },
);
Deno.copyFileSync("LICENSE", `./npm/${Deno.args[0]}/LICENSE`);
Deno.copyFileSync("README.md", `./npm/${Deno.args[0]}/README.md`);
// await emptyDir("./npm/" + Deno.args[0] + "/src");
// await emptyDir("./npm/" + Deno.args[0] + "/esm/test");
// await emptyDir("./npm/" + Deno.args[0] + "/script/test");
