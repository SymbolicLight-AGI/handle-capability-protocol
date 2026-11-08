export class HcpError extends Error {
  constructor(message, code = 'HCP_ERROR', details = {}) {
    super(message);
    this.name = 'HcpError';
    this.code = code;
    this.details = details;
  }
}

export class PolicyDeniedError extends HcpError {
  constructor(message, details = {}) {
    super(message, 'POLICY_DENIED', details);
    this.name = 'PolicyDeniedError';
  }
}

export class NotFoundError extends HcpError {
  constructor(message, details = {}) {
    super(message, 'NOT_FOUND', details);
    this.name = 'NotFoundError';
  }
}

export class InvalidInputError extends HcpError {
  constructor(message, details = {}) {
    super(message, 'INVALID_INPUT', details);
    this.name = 'InvalidInputError';
  }
}

export class InvalidParamsError extends HcpError {
  constructor(message, details = {}) {
    super(message, 'INVALID_PARAMS', details);
    this.name = 'InvalidParamsError';
  }
}
