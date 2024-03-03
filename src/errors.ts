/**
 * The base error class of kyber-ts.
 */
export class MlKemError extends Error {
  public constructor(e: unknown) {
    let message: string;

    if (e instanceof Error) {
      message = e.message;
    } else if (typeof e === "string") {
      message = e;
    } else {
      message = "";
    }
    super(message);

    this.name = this.constructor.name;
  }
}
