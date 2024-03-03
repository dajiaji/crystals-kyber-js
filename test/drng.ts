import { KyberBase } from "../src/kyberBase.ts";
import { shake128 } from "../src/deps.ts";

type GetRandomValuesInputType = Parameters<
  typeof Crypto.prototype.getRandomValues
>[0];

export function getDeterministicKyberClass<T extends typeof KyberBase>(
  KyberClass: T,
): typeof KyberBase {
  // @ts-ignore mixing constructor error expecting any[] as argument
  return class DeterministicKyber extends KyberClass {
    // deno-lint-ignore require-await
    async _setup() {
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
