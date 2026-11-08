export const TASK_STATES = new Set([
  'PENDING',
  'RUNNING',
  'WAITING_APPROVAL',
  'WAITING_INPUT',
  'PAUSED',
  'CANCELLING',
  'CANCELLED',
  'FAILED',
  'COMPLETED'
]);

export const EFFECT_RISK = {
  read: 1,
  write: 3,
  execute: 4,
  external_send: 5
};

export const RISK_SCORE = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export const BILATERAL_FLOW_CONSTRAINTS = Object.freeze({
  max_uses: 1,
  direct_runtime_transfer: true,
  caller_payload_forbidden: true
});
