declare const Deno: undefined;
const isDeno = () => typeof Deno !== "undefined";

export function testVectorPath(): string {
  if (isDeno()) {
    return "./test/vectors";
  }
  return "../../../packages/hqc/test/vectors";
}

export function hexToBytes(v: string): Uint8Array {
  if (v.length % 2 !== 0 || /[^\da-f]/i.test(v)) {
    throw new Error("Not hex string.");
  }
  const res = new Uint8Array(v.length / 2);
  for (let i = 0; i < res.length; i++) {
    res[i] = parseInt(v.substring(2 * i, 2 * i + 2), 16);
  }
  return res;
}

export function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const ret = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    ret.set(a, offset);
    offset += a.length;
  }
  return ret;
}

/**
 * Parses a KAT response file of the NIST KAT generator (PQCkemKAT_*.rsp):
 * `label = hex` lines, which are grouped by label in the order of appearance.
 * Comments and `count` lines are skipped.
 */
export function parseKAT(data: string): { [label: string]: Uint8Array[] } {
  const parsed: { [label: string]: Uint8Array[] } = {};
  for (const line of data.split("\n")) {
    const pos = line.indexOf(" = ");
    if (line.startsWith("#") || pos < 0) continue;
    const label = line.substring(0, pos);
    if (label === "count") continue;
    (parsed[label] ??= []).push(hexToBytes(line.substring(pos + 3).trim()));
  }
  return parsed;
}

/**
 * Parses an intermediate values file of the HQC reference implementation:
 * `label: value` lines under `### SECTION ###` headers. The values of a
 * label are kept in the order of appearance within its section.
 */
export function parseIntermediates(
  data: string,
): { [section: string]: { [label: string]: string[] } } {
  const parsed: { [section: string]: { [label: string]: string[] } } = {};
  let section = "";
  for (const line of data.split("\n")) {
    const header = line.match(/^### (\w+) ###$/);
    if (header !== null) {
      section = header[1];
      continue;
    }
    const pos = line.indexOf(": ");
    if (section === "" || line.startsWith("#") || pos < 0) continue;
    const labels = (parsed[section] ??= {});
    (labels[line.substring(0, pos)] ??= []).push(
      line.substring(pos + 2).trim(),
    );
  }
  return parsed;
}

/** A sample of a Reed-Solomon test vector file (rs.tv). */
export interface RsSample {
  scenario: string;
  message: Uint8Array;
  codeword: Uint8Array;
  corrupted: Uint8Array;
  syndromes: Uint8Array;
  sigma: Uint8Array;
  errorPositions: Uint8Array;
  decoded: Uint8Array;
}

/**
 * Parses a Reed-Solomon test vector file of the HQC reference implementation
 * (rs.tv): samples which start with `---`, of `label = octets` lines.
 */
export function parseRsTv(data: string): RsSample[] {
  const samples: RsSample[] = [];
  let scenario = "";
  let fields: { [label: string]: Uint8Array } | undefined;
  const flush = () => {
    if (fields !== undefined) {
      samples.push({
        scenario,
        message: fields["message"],
        codeword: fields["codeword"],
        corrupted: fields["corrupted"],
        syndromes: fields["syndromes"],
        sigma: fields["sigma"],
        errorPositions: fields["error_positions"],
        decoded: fields["decoded"],
      });
    }
    fields = undefined;
  };
  for (const line of data.split("\n")) {
    const begin = line.match(/^# ===== BEGIN SCENARIO: (\w+) /);
    if (begin !== null) {
      flush();
      scenario = begin[1];
    } else if (line.startsWith("---")) {
      flush();
      fields = {};
    } else if (!line.startsWith("#") && fields !== undefined) {
      const pos = line.indexOf(" = ");
      if (pos < 0) continue;
      fields[line.substring(0, pos)] = hexToBytes(
        line.substring(pos + 3).replaceAll(" ", "").trim(),
      );
    }
  }
  flush();
  return samples;
}
