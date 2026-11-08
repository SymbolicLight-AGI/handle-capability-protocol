// Integrity-protected, principal/request-bound approval state. The trusted host
// supplies the approval response; integrity alone is not proof of human consent.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { HcpError } from './errors.js';

export const MRTR_STATE_VERSION = 'hcp.mrtr/0.1';

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(',')}}`;
}

export function requestDigest(method, params) {
  return createHmac('sha256', 'hcp.mrtr.digest').update(canonical({ method, params })).digest('hex');
}

function sign(secret, claims) {
  return createHmac('sha256', secret).update(canonical(claims)).digest('hex');
}

function equalHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length || !/^[0-9a-f]{64}$/i.test(left) || !/^[0-9a-f]{64}$/i.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

export function createRequestStateAuthority({ secret = randomBytes(32), ttlMs = 300000, clock = () => new Date() } = {}) {
  const consumed = new Set();

  return {
    // Mints a state blob bound to the principal that will present it and to the
    // exact request it resumes.
    mint({ principal, capability, digest, inputId = 'approval' }) {
      const claims = {
        v: MRTR_STATE_VERSION,
        sub: principal ?? null,
        cap: capability ?? null,
        req: digest,
        input_id: inputId,
        jti: randomBytes(16).toString('hex'),
        exp: new Date(clock().getTime() + ttlMs).toISOString()
      };
      return Buffer.from(JSON.stringify({ ...claims, mac: sign(secret, claims) })).toString('base64url');
    },

    // Verifies and consumes. Every failure is a distinct, stable reason so a
    // denial can be audited and attributed.
    verify(encodedState, { principal, digest, consume = true }) {
      let state;
      try {
        if (typeof encodedState !== 'string' || !/^[A-Za-z0-9_-]+$/.test(encodedState) || encodedState.length > 16384) throw new Error();
        state = JSON.parse(Buffer.from(encodedState, 'base64url').toString('utf8'));
        if (!state || typeof state !== 'object' || Array.isArray(state)) throw new Error();
      } catch {
        throw new HcpError('MRTR requestState must be an encoded opaque string', 'MRTR_STATE_INVALID');
      }
      const { mac, ...claims } = state;
      if (claims.v !== MRTR_STATE_VERSION) {
        throw new HcpError('MRTR requestState has an unsupported version', 'MRTR_STATE_INVALID', {
          expected: MRTR_STATE_VERSION,
          received: claims.v ?? null
        });
      }
      if (!equalHex(mac, sign(secret, claims))) {
        throw new HcpError('MRTR requestState failed integrity verification', 'MRTR_STATE_INVALID', {
          principal: principal ?? null,
          subject: claims.sub ?? null
        });
      }
      if (claims.sub !== (principal ?? null)) {
        throw new HcpError('MRTR requestState was issued for a different principal', 'MRTR_SUBJECT_MISMATCH', {
          principal: principal ?? null,
          subject: claims.sub ?? null
        });
      }
      if (claims.req !== digest) {
        throw new HcpError('MRTR requestState does not match the resumed request', 'MRTR_REQUEST_MISMATCH', {
          principal: principal ?? null,
          expected: claims.req,
          received: digest
        });
      }
      if (!Number.isFinite(new Date(claims.exp).getTime()) || new Date(claims.exp).getTime() <= clock().getTime()) {
        throw new HcpError('MRTR requestState has expired', 'MRTR_STATE_EXPIRED', {
          principal: principal ?? null,
          expires_at: claims.exp
        });
      }
      if (consumed.has(claims.jti)) {
        throw new HcpError('MRTR requestState has already been used', 'MRTR_STATE_REPLAYED', {
          principal: principal ?? null,
          jti: claims.jti
        });
      }
      if (consume) consumed.add(claims.jti);
      return { ...claims };
    }
  };
}

// Only the existing tools/call approval form is supported here.
export function toInputRequiredResult(task, requestState, inputId = task.task_id) {
  return {
    resultType: 'input_required',
    inputRequests: {
      [inputId]: {
        method: 'elicitation/create',
        params: {
          mode: 'form',
          message: `Approve ${task.capability ?? 'the requested capability'}?`,
          requestedSchema: {
            type: 'object',
            properties: { approved: { type: 'boolean', title: 'Approve execution' } },
            required: ['approved']
          }
        }
      }
    },
    requestState
  };
}
