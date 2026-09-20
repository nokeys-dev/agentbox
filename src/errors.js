export class GateError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function assert(condition, message) {
  if (!condition) throw new Error(message);
}
