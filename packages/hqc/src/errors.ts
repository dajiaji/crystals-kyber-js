/**
 * The base error class of hqc.
 */
export class HqcError extends Error {
  /**
   * @param e The error, or the message of the error, which this one wraps.
   */
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
