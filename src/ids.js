import { randomBytes } from 'node:crypto';

export function makeId(prefix) {
  return `${prefix}_${randomBytes(8).toString('hex')}`;
}

export function nowIso(clock = () => new Date()) {
  return clock().toISOString();
}
