// Request-local correlation and optional JSONL persistence; never accepts an identity from untrusted headers.
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { matchesAuditFilter } from './core/matching.js';

const context = new AsyncLocalStorage();

export function withAuditAttempt(runtime, details, fn) {
  const parent = context.getStore();
  return context.run({ ...parent, runtime, attempt_id: parent?.attempt_id ?? randomUUID(), ...details }, fn);
}

export function createAuditEntries({ auditLogPath = null, onEntry = null, maxEntries = null } = {}) {
  const entries = [];
  const cap = Number.isInteger(maxEntries) && maxEntries > 0 ? maxEntries : null;
  let dirEnsured = false;
  Object.defineProperty(entries, 'push', {
    value(...events) {
      const current = context.getStore();
      const enriched = events.map((event) => (current ? {
        ...event,
        attempt_id: current.attempt_id,
        method: event.method ?? current.method,
        identity_status: current.principal == null ? 'unavailable' : 'authenticated'
      } : event));
      const result = Array.prototype.push.apply(this, enriched);
      if (auditLogPath) {
        if (!dirEnsured) {
          mkdirSync(dirname(auditLogPath), { recursive: true });
          dirEnsured = true;
        }
        const lines = enriched.map((event) => `${JSON.stringify(toPersistedAuditEntry(event))}\n`).join('');
        if (lines) appendFileSync(auditLogPath, lines, { encoding: 'utf8', mode: 0o600 });
      }
      if (typeof onEntry === 'function') {
        for (const event of enriched) onEntry(event);
      }
      if (cap !== null && this.length > cap) {
        this.splice(0, this.length - cap);
      }
      return this.length ?? result;
    }
  });
  return entries;
}

function payloadDigest(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value ?? null);
  return {
    omitted: 'payload',
    digest: `sha256:${createHash('sha256').update(raw).digest('hex')}`,
    bytes: Buffer.byteLength(raw, 'utf8')
  };
}

// The durable audit log records decisions and data-flow metadata, never tool
// payloads: provider results are replaced by a digest so that .hcp/audit.jsonl
// cannot become a plaintext copy of handle-protected data.
export function toPersistedAuditEntry(entry) {
  if (!entry || typeof entry !== 'object') return entry;
  const payload = entry.event?.payload;
  if (!payload || typeof payload !== 'object' || payload.result === undefined) return entry;
  return {
    ...entry,
    event: {
      ...entry.event,
      payload: {
        ...payload,
        result: payloadDigest(payload.result)
      }
    }
  };
}

export function readAuditLogEntries(auditLogPath, filter = {}) {
  if (!auditLogPath || !existsSync(auditLogPath)) return [];
  const raw = readFileSync(auditLogPath, 'utf8');
  const entries = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (matchesAuditFilter(parsed, filter)) {
        entries.push(parsed);
      }
    } catch {
      // Ignore malformed trailing lines
    }
  }
  return entries;
}

export function tailAuditLogEntries(auditLogPath, { limit = 50, filter = {} } = {}) {
  const matching = readAuditLogEntries(auditLogPath, filter);
  const effectiveLimit = Number.isInteger(limit) && limit > 0 ? limit : 50;
  return matching.slice(Math.max(0, matching.length - effectiveLimit));
}

export function auditRequestDenial(reason, details = {}) {
  const current = context.getStore();
  if (!current?.runtime) return;
  current.runtime.auditEntries.push({
    type: details.stage === 'transport' ? 'HTTP_REQUEST_DENIED' : 'MCP_REQUEST_DENIED',
    at: new Date().toISOString(),
    principal: current.principal ?? null,
    identity_status: current.principal == null ? 'unavailable' : 'authenticated',
    method: details.method ?? current.method ?? 'unknown',
    operation: details.method ?? current.method ?? 'unknown',
    object: details.object ?? current.object ?? 'unavailable',
    decision: 'deny',
    reason,
    stage: details.stage ?? 'protocol',
    request_id: details.request_id ?? current.request_id ?? null
  });
}
