declare const Deno: undefined;
const isDeno = () => typeof Deno !== "undefined";

export function testVectorPath(): string {
  if (isDeno()) {
    return "./test/vectors";
  }
  return "../../test/vectors";
}

export function hexToBytes(v: string): Uint8Array {
  if (v.length === 0) {
    return new Uint8Array([]);
  }
  const res = v.match(/[\da-f]{2}/gi);
  if (res == null) {
    throw new Error("Not hex string.");
  }
  return new Uint8Array(res.map(function (h) {
    return parseInt(h, 16);
  }));
}

export function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToDec(hexString: string): number {
  return parseInt(hexString, 16);
}

export function parseKAT(data: string) {
  const textByLine = data.trim().split("\n");
  const parsed: { [label: string]: Uint8Array[] } = {};

  for (let i = 0; i < textByLine.length; i++) {
    const [label, hexValue] = textByLine[i].split(" = ");
    if (label === "count") continue;
    const value = hexToBytes(hexValue);
    if (parsed[label]) {
      parsed[label].push(value);
    } else {
      parsed[label] = [value];
    }
  }

  return parsed;
}
