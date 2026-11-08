import { createHash } from 'node:crypto';

export function digest(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  return `sha256:${createHash('sha256').update(raw).digest('hex')}`;
}
