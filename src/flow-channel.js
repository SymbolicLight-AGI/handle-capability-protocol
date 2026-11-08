import https from 'node:https';
import tls from 'node:tls';
import { randomUUID, createHash, createPublicKey } from 'node:crypto';

export const FLOW_CHANNEL_PROTOCOL = 'hcp.flow-channel/1';

function fingerprint(value) {
  const normalized = String(value ?? '').toLowerCase().replace(/^sha256:/, '').replaceAll(':', '');
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw new TypeError('a SHA-256 certificate fingerprint is required');
  return normalized;
}

function emit(onEvent, event) {
  if (onEvent) onEvent(event);
}

function errorResponse(code, message, status = 400) {
  return Object.assign(new Error(message), { code, httpStatus: status });
}

function readJson(stream, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let done = false;
    function fail(error) {
      if (done) return;
      done = true;
      reject(error);
    }
    stream.on('data', (chunk) => {
      length += chunk.length;
      if (length > maxBytes) {
        fail(errorResponse('BODY_TOO_LARGE', 'flow channel body exceeds configured limit', 413));
        stream.resume();
      } else if (!done) chunks.push(chunk);
    });
    stream.once('end', () => {
      if (done) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(errorResponse('INVALID_JSON', 'flow channel requires valid JSON')); }
    });
    stream.once('error', fail);
    stream.once('aborted', () => fail(errorResponse('TRANSPORT_ABORTED', 'flow channel request aborted')));
  });
}

function peerDescriptor(peer) {
  const descriptor = peer.descriptor;
  const configuredKey = peer.public_key_fingerprint ?? peer.key_fingerprint;
  const descriptorKey = descriptor?.public_key_fingerprint ?? descriptor?.key_fingerprint;
  if (!descriptor || descriptor.domain_id !== peer.domain_id ||
      descriptorKey !== configuredKey) {
    throw new TypeError('peer descriptor must match trusted domain and signing-key fingerprint');
  }
  const actualKeyFingerprint = `sha256:${createHash('sha256').update(createPublicKey(descriptor.public_key_pem)
    .export({ type: 'spki', format: 'der' })).digest('hex')}`;
  if (actualKeyFingerprint !== descriptorKey) {
    throw new TypeError('trusted descriptor signing key differs from its fingerprint');
  }
  return structuredClone(descriptor);
}

/** Endpoints and signing descriptors come only from trusted local configuration. */
export function createFlowChannel({ peer, tls: identity, localDomainId, timeoutMs = 10000,
  maxBodyBytes = 16 * 1024 * 1024, maxSockets = 64, onEvent }) {
  if (!peer || !identity?.ca || !identity?.cert || !identity?.key || !localDomainId) {
    throw new TypeError('flow channel requires peer configuration and mutual TLS identity');
  }
  const endpoint = new URL(peer.endpoint);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new TypeError('trusted flow endpoint must be an HTTPS URL without credentials, query or fragment');
  }
  const expectedFingerprint = fingerprint(peer.certificate_fingerprint);
  const descriptor = peerDescriptor(peer);
  function validateCertificate(host, certificate) {
    const hostnameError = tls.checkServerIdentity(host, certificate);
    if (hostnameError) return hostnameError;
    if (fingerprint(certificate.fingerprint256) !== expectedFingerprint) {
      return errorResponse('PEER_CERTIFICATE_MISMATCH', 'flow peer certificate does not match trusted pin');
    }
  }
  // A peer-bound validator belongs to its dedicated agent. Node deliberately
  // discards sockets for per-request identity callbacks, preventing reuse.
  const agent = new https.Agent({ keepAlive: true, maxSockets, maxCachedSessions: 0,
    ca: identity.ca, cert: identity.cert, key: identity.key, rejectUnauthorized: true,
    minVersion: 'TLSv1.3', checkServerIdentity: validateCertificate });

  async function call(operation, payload, context = {}) {
    if (typeof operation !== 'string' || !/^[a-z][a-zA-Z0-9]*$/.test(operation)) throw new TypeError('invalid flow operation');
    const attemptId = context.attempt_id ?? randomUUID();
    if (typeof attemptId !== 'string' || !attemptId || attemptId.length > 256) throw new TypeError('invalid attempt_id');
    const encoded = Buffer.from(JSON.stringify({ protocol: FLOW_CHANNEL_PROTOCOL, operation,
      attempt_id: attemptId, sender_domain: localDomainId, payload }));
    if (encoded.length > maxBodyBytes) throw errorResponse('BODY_TOO_LARGE', 'flow request exceeds configured limit', 413);
    emit(onEvent, { type: 'channel_request', direction: 'outbound', attempt_id: attemptId,
      operation, peer_domain: peer.domain_id, bytes: encoded.length });
    return await new Promise((resolve, reject) => {
      const request = https.request(endpoint, {
        method: 'POST', agent, ca: identity.ca, cert: identity.cert, key: identity.key,
        rejectUnauthorized: true, minVersion: 'TLSv1.3',
        headers: { 'content-type': 'application/json', 'content-length': encoded.length },
        timeout: timeoutMs
      }, async (response) => {
        try {
          emit(onEvent, { type: 'channel_response_headers', attempt_id: attemptId, operation, peer_domain: peer.domain_id,
            reused_socket: request.reusedSocket === true, connection: response.headers.connection ?? null });
          if (!response.socket.authorized || fingerprint(response.socket.getPeerCertificate().fingerprint256) !== expectedFingerprint) {
            throw errorResponse('PEER_CERTIFICATE_MISMATCH', 'response peer is not trusted');
          }
          const envelope = await readJson(response, maxBodyBytes);
          if (!envelope || envelope.protocol !== FLOW_CHANNEL_PROTOCOL || envelope.attempt_id !== attemptId ||
              envelope.domain_id !== peer.domain_id || envelope.operation !== operation) {
            throw errorResponse('RESPONSE_CONTEXT_MISMATCH', 'flow response context does not match request');
          }
          emit(onEvent, { type: 'channel_response', direction: 'inbound', attempt_id: attemptId,
            operation, peer_domain: peer.domain_id, status: response.statusCode });
          if (response.statusCode !== 200 || !envelope.ok) {
            const error = errorResponse(envelope.error?.code ?? 'CHANNEL_REJECTED',
              envelope.error?.message ?? 'flow peer rejected operation', response.statusCode);
            if (envelope.error?.details !== undefined) error.details = envelope.error.details;
            throw error;
          }
          resolve(envelope.result);
        } catch (error) { reject(error); }
      });
      request.once('timeout', () => request.destroy(errorResponse('TRANSPORT_TIMEOUT', 'flow channel request timed out', 504)));
      request.once('error', (error) => {
        error.transport_error = true;
        emit(onEvent, { type: 'channel_error', attempt_id: attemptId, operation,
          peer_domain: peer.domain_id, reason: error.code ?? error.name });
        reject(error);
      });
      // Deliberately no automatic retry: authorization and execution are one-use operations.
      request.end(encoded);
    });
  }

  return {
    call,
    async describePeer(context) {
      const remote = await call('describePeer', {}, context);
      if (remote?.domain_id !== descriptor.domain_id ||
          (remote?.public_key_fingerprint ?? remote?.key_fingerprint) !== (descriptor.public_key_fingerprint ?? descriptor.key_fingerprint) ||
          remote?.public_key_pem !== descriptor.public_key_pem || remote?.protocol !== descriptor.protocol) {
        throw errorResponse('PEER_DESCRIPTOR_MISMATCH', 'remote signing descriptor differs from trusted configuration');
      }
      return remote;
    },
    receive: (bundle, context) => call('receive', bundle, context),
    commitAuthorize: (challenge, context) => call('commitAuthorize', challenge, context),
    queryReceipt: (query, context) => call('queryReceipt', query, context),
    flowDomainDescribe: () => structuredClone(descriptor),
    flowReceive: (bundle, options = {}) => call('receive', bundle, { attempt_id: options.attempt_id ?? bundle?.attempt_id }),
    flowCommitAuthorize: (challenge, options = {}) => call('commitAuthorize', challenge,
      { attempt_id: options.attempt_id ?? challenge?.attempt_id }),
    close: () => agent.destroy()
  };
}

/** Authenticated operation router. It never trusts envelope sender_domain as identity. */
export function createFlowChannelServer({ tls: identity, domainId, peers, handlers,
  host = '127.0.0.1', port = 0, path = '/flow', maxBodyBytes = 16 * 1024 * 1024,
  requestTimeoutMs = 15000, onEvent }) {
  if (!domainId || !identity?.ca || !identity?.cert || !identity?.key || !Array.isArray(peers) || !handlers) {
    throw new TypeError('flow server requires domain identity, trusted peers and handlers');
  }
  const trustedPeers = new Map();
  for (const peer of peers) {
    const certPin = fingerprint(peer.certificate_fingerprint);
    if (trustedPeers.has(certPin) || !peer.domain_id || !(peer.public_key_fingerprint ?? peer.key_fingerprint) || !Array.isArray(peer.operations)) {
      throw new TypeError('flow peers require unique certificate/domain/key and permitted operations');
    }
    trustedPeers.set(certPin, { ...peer, operations: new Set(peer.operations) });
  }
  const server = https.createServer({ ca: identity.ca, cert: identity.cert, key: identity.key,
    requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, async (request, response) => {
    let attemptId = null;
    let operation = null;
    let authenticatedPeer;
    function reply(status, result) {
      if (response.destroyed || response.writableEnded) return;
      const data = Buffer.from(JSON.stringify({ protocol: FLOW_CHANNEL_PROTOCOL, domain_id: domainId,
        attempt_id: attemptId, operation, ...result }));
      if (data.length > maxBodyBytes) {
        response.writeHead(500, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ protocol: FLOW_CHANNEL_PROTOCOL, domain_id: domainId, attempt_id: attemptId,
          operation, ok: false, error: { code: 'RESPONSE_TOO_LARGE', message: 'flow response exceeds configured limit' } }));
        return;
      }
      response.writeHead(status, { 'content-type': 'application/json', 'content-length': data.length });
      response.end(data);
    }
    try {
      if (!request.socket.authorized) throw errorResponse('UNAUTHENTICATED_PEER', 'mutual TLS authentication required', 401);
      authenticatedPeer = trustedPeers.get(fingerprint(request.socket.getPeerCertificate().fingerprint256));
      if (!authenticatedPeer) throw errorResponse('UNTRUSTED_PEER', 'TLS peer is not a configured flow domain', 403);
      if (request.method !== 'POST' || request.url !== path) throw errorResponse('INVALID_ENDPOINT', 'invalid flow endpoint', 404);
      if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
        throw errorResponse('INVALID_CONTENT_TYPE', 'flow channel requires application/json', 415);
      }
      const contentLength = Number(request.headers['content-length']);
      if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) throw errorResponse('BODY_TOO_LARGE', 'flow body exceeds configured limit', 413);
      const envelope = await readJson(request, maxBodyBytes);
      operation = envelope?.operation ?? null;
      attemptId = envelope?.attempt_id ?? null;
      if (!envelope || Array.isArray(envelope) || envelope.protocol !== FLOW_CHANNEL_PROTOCOL ||
          typeof operation !== 'string' || typeof attemptId !== 'string' || !attemptId || attemptId.length > 256) {
        throw errorResponse('INVALID_ENVELOPE', 'invalid flow channel envelope');
      }
      if (envelope.sender_domain !== authenticatedPeer.domain_id) {
        throw errorResponse('SENDER_DOMAIN_MISMATCH', 'claimed sender differs from authenticated domain', 403);
      }
      if (!authenticatedPeer.operations.has(operation) || typeof handlers[operation] !== 'function') {
        throw errorResponse('OPERATION_NOT_PERMITTED', 'operation is not permitted for authenticated peer', 403);
      }
      const context = {
        attempt_id: attemptId,
        peer: { domain_id: authenticatedPeer.domain_id, public_key_fingerprint: authenticatedPeer.public_key_fingerprint ?? authenticatedPeer.key_fingerprint,
          key_fingerprint: authenticatedPeer.public_key_fingerprint ?? authenticatedPeer.key_fingerprint,
          certificate_fingerprint: authenticatedPeer.certificate_fingerprint },
        domain_id: domainId
      };
      emit(onEvent, { type: 'channel_request', direction: 'inbound', attempt_id: attemptId,
        operation, peer_domain: authenticatedPeer.domain_id });
      const result = await handlers[operation](envelope.payload, context);
      reply(200, { ok: true, result });
    } catch (error) {
      emit(onEvent, { type: 'channel_denied', attempt_id: attemptId, operation,
        peer_domain: authenticatedPeer?.domain_id ?? null,
        identity_available: Boolean(authenticatedPeer), reason: error.code ?? error.name });
      const status = error.httpStatus ?? (error.code === 'POLICY_DENIED' ? 403 : 400);
      reply(status, { ok: false, error: { code: error.code ?? 'CHANNEL_HANDLER_ERROR', message: error.message,
        ...(error.details === undefined ? {} : { details: error.details }) } });
    }
  });
  server.requestTimeout = requestTimeoutMs;
  server.headersTimeout = requestTimeoutMs;
  server.on('tlsClientError', (error) => emit(onEvent, { type: 'channel_denied', attempt_id: null,
    operation: null, peer_domain: null, identity_available: false, reason: error.code ?? error.name }));
  return {
    server,
    async listen() {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => { server.off('error', reject); resolve(); });
      });
      const address = server.address();
      return { ...address, endpoint: `https://${host.includes(':') ? `[${host}]` : host}:${address.port}${path}` };
    },
    address: () => server.address(),
    async close() {
      server.closeIdleConnections();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  };
}
