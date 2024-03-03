import rollupCommonjs from "@rollup/plugin-commonjs";
import rollupResolve from "@rollup/plugin-node-resolve";

import rollupReplace from "@rollup/plugin-replace";
import { fromRollup } from "@web/dev-server-rollup";

const commonjs = fromRollup(rollupCommonjs);
const replace = fromRollup(rollupReplace);
const resolve = fromRollup(rollupResolve); // called as part of `plugins` instead of through the `nodeResolve` config as we need it to run after `replace()`

export default {
  plugins: [
    replace({ "import('crypto')": "void()" }),
    resolve({ browser: true }),
    commonjs(),
  ],
};
