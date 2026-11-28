/**
 * The getter of %TypedArray%.prototype[Symbol.toStringTag], which returns the
 * built-in type name of a typed array and undefined for anything else. Unlike
 * `instanceof` or `constructor.name`, it also identifies a Uint8Array, or an
 * instance of its subclass, which was created in another realm (an iframe or
 * node:vm), and it cannot be overridden by the value.
 */
const typedArrayName = /* @__PURE__ */ (() =>
  Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    Symbol.toStringTag,
  )!.get as (this: unknown) => string | undefined)();

/**
 * Asserts that an argument is a Uint8Array. Another type such as ArrayBuffer
 * has `byteLength` but no elements to read, so it would be hashed as empty.
 */
export function assertBytes(value: unknown, name: string): void {
  if (typedArrayName.call(value) !== "Uint8Array") {
    throw new Error(`${name} must be a Uint8Array`);
  }
}
