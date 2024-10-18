import type { MlKemBase } from "../src/mlKemBase.ts";
import { shake128 } from "../src/deps.ts";

type GetRandomValuesInputType = Parameters<
  typeof Crypto.prototype.getRandomValues
>[0];

export function getDeterministicMlKemClass<T extends typeof MlKemBase>(
  MlKemClass: T,
): typeof MlKemBase {
  // @ts-ignore mixing constructor error expecting any[] as argument
  return class DeterministicMlKem extends MlKemClass {
    // deno-lint-ignore require-await
    override async _setup() {
      // @ts-ignore private accessor
      if (this._api !== undefined) {
        return;
      }
      const shakeInstance = shake128.create({});
      // @ts-ignore private accessor
      this._api = {
        getRandomValues: <T extends GetRandomValuesInputType>(buffer: T) => {
          if (!(buffer instanceof Uint8Array)) throw new Error("Unsupported");
          shakeInstance.xofInto(buffer);
          return buffer;
        },
      };
    }
  };
}
