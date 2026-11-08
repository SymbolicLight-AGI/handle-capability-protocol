import { withAuditAttempt, auditRequestDenial } from './audit-context.js';
import http from 'node:http';
import { TextDecoder } from 'node:util';
import { HcpError } from './errors.js';
import { makeId } from './ids.js';
import { createHcpJsonRpcDispatcher } from './jsonrpc.js';
import {
  createMcpClientShimDispatcher,
  MCP_STATELESS_PROTOCOL_VERSION,
  MCP_SUPPORTED_PROTOCOL_VERSIONS
} from './mcp-adapter.js';

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

function writeJson(response, statusCode, value, headers = {}) {
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    ...headers
  });
  response.end(JSON.stringify(value));
}

function writeEmpty(response, statusCode, headers = {}) {
  response.writeHead(statusCode, headers);
  response.end();
}

function writeError(response, statusCode, code, message, headers = {}, details = null) {
  auditRequestDenial(code, { stage: 'transport' });
  writeJson(response, statusCode, {
    error: {
      code,
      message,
      ...(details ? { details } : {})
    }
  }, headers);
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mcpJsonRpcError(id, code, message, data = undefined) {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data })
    }
  };
}

function writeMcpJsonRpcError(response, statusCode, payload, code, message, data = undefined, headers = {}) {
  auditRequestDenial(message, { stage: 'transport', method: payload?.method, object: mcpRequestName(payload), request_id: payload?.id });
  writeJson(response, statusCode, mcpJsonRpcError(payload?.id, code, message, data), headers);
}

function getHeader(request, name) {
  const value = request.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function decodeMirroredName(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (value.startsWith('=?base64?')) {
    const match = /^=\?base64\?([A-Za-z0-9+/]+={0,2})\?=$/.exec(value);
    if (!match) return null;
    const bytes = Buffer.from(match[1], 'base64');
    if (bytes.toString('base64') !== match[1]) return null;
    try {
      return utf8Decoder.decode(bytes);
    } catch {
      return null;
    }
  }
  // A plain value matching the sentinel must be encoded, and values outside
  // visible ASCII (or with edge whitespace) cannot be used as plain headers.
  if (value.startsWith('=?base64?') || !/^[\x20-\x7E\t]+$/.test(value) || value.trim() !== value) return null;
  return value;
}

function acceptsModernMcpResponse(request) {
  const accepted = (getHeader(request, 'accept') ?? '').split(',').map((part) => {
    const [type, ...parameters] = part.trim().toLowerCase().split(';');
    const quality = parameters.find((parameter) => parameter.trim().startsWith('q='));
    return { type: type.trim(), q: quality ? Number(quality.trim().slice(2)) : 1 };
  });
  return ['application/json', 'text/event-stream'].every((type) =>
    accepted.some((item) => item.type === type && item.q > 0 && item.q <= 1));
}

function allowedRequestOrigin(request, configuredOrigins) {
  if (Array.isArray(request.rawHeaders)) {
    let originCount = 0;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      if (request.rawHeaders[index].toLowerCase() === 'origin') originCount += 1;
    }
    if (originCount > 1) return false;
  }
  if (Array.isArray(request.headers.origin)) return false;
  const origin = getHeader(request, 'origin');
  if (origin === undefined) return true;
  try {
    const parsed = new URL(origin);
    if (parsed.origin !== origin || !['http:', 'https:'].includes(parsed.protocol)) return false;
    const localHost = request.socket.localAddress;
    const localAddress = localHost.includes(':') ? `[${localHost}]` : localHost;
    const localOrigin = new URL(`http://${localAddress}:${request.socket.localPort}`).origin;
    return origin === localOrigin || configuredOrigins.has(origin);
  } catch {
    return false;
  }
}

function mcpRequestName(payload) {
  const params = isObject(payload?.params) ? payload.params : {};
  if (typeof params.name === 'string') return params.name;
  if (typeof params.uri === 'string') return params.uri;
  if (typeof params.taskId === 'string') return params.taskId;
  return null;
}

function validateStatelessMcpHttpRequest(request, response, payload, headers) {
  if (!isObject(payload) || payload.jsonrpc !== '2.0' || typeof payload.method !== 'string') {
    writeMcpJsonRpcError(response, 400, payload, -32600, 'INVALID_REQUEST', undefined, headers);
    return false;
  }

  if (!acceptsModernMcpResponse(request)) {
    writeMcpJsonRpcError(response, 406, payload, -32600, 'NOT_ACCEPTABLE', {
      required: ['application/json', 'text/event-stream']
    }, headers);
    return false;
  }

  const requestVersion = getHeader(request, 'mcp-protocol-version');
  if (requestVersion !== MCP_STATELESS_PROTOCOL_VERSION) {
    writeMcpJsonRpcError(response, 400, payload, -32022, 'UNSUPPORTED_PROTOCOL_VERSION', {
      supported: MCP_SUPPORTED_PROTOCOL_VERSIONS,
      requested: requestVersion ?? null
    }, headers);
    return false;
  }

  const methodHeader = getHeader(request, 'mcp-method');
  if (methodHeader !== payload.method) {
    writeMcpJsonRpcError(response, 400, payload, -32020, 'HEADER_MISMATCH', {
      header: 'Mcp-Method',
      expected: payload.method,
      received: methodHeader ?? null
    }, headers);
    return false;
  }

  const bodyName = mcpRequestName(payload);
  const nameRequired = ['tools/call', 'resources/read', 'prompts/get'].includes(payload.method);
  const nameHeader = getHeader(request, 'mcp-name');
  if (nameRequired && (bodyName === null || decodeMirroredName(nameHeader) !== bodyName)) {
    writeMcpJsonRpcError(response, 400, payload, -32020, 'HEADER_MISMATCH', {
      header: 'Mcp-Name',
      expected: bodyName,
      received: nameHeader ?? null
    }, headers);
    return false;
  }

  const meta = isObject(payload.params) && isObject(payload.params._meta) ? payload.params._meta : null;
  if (!meta || meta['io.modelcontextprotocol/protocolVersion'] !== MCP_STATELESS_PROTOCOL_VERSION) {
    writeMcpJsonRpcError(response, 400, payload, -32602, 'INVALID_PARAMS', {
      required: 'params._meta.io.modelcontextprotocol/protocolVersion',
      expected: MCP_STATELESS_PROTOCOL_VERSION,
      received: meta?.['io.modelcontextprotocol/protocolVersion'] ?? null
    }, headers);
    return false;
  }

  return true;
}

function rejectVersionMismatch(request, response, {
  header,
  expected,
  headers
}) {
  const received = getHeader(request, header);
  if (!received || received === expected) return false;
  writeError(
    response,
    400,
    'PROTOCOL_VERSION_MISMATCH',
    `${header} must be ${expected}`,
    headers,
    { header, expected, received }
  );
  return true;
}

function rejectSessionMismatch(request, response, {
  expected,
  headers,
  header = 'hcp-session-id',
  aliases = []
}) {
  const received = getHeader(request, header) ?? (
    aliases
      .map((alias) => getHeader(request, alias))
      .find((value) => value !== undefined && value !== null)
  );
  if (!received || received === expected) return false;
  writeError(
    response,
    400,
    'SESSION_ID_MISMATCH',
    `${header} must be ${expected}`,
    headers,
    { header, expected, received }
  );
  return true;
}

function parseSinceEvent(request, url) {
  const explicitSinceEvent = url.searchParams.get('since_event');
  const lastEventId = request.headers['last-event-id'];
  const rawValue = explicitSinceEvent ?? (Array.isArray(lastEventId) ? lastEventId[0] : lastEventId) ?? '0';
  const parsed = Number.parseInt(rawValue, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function parseWaitMs(url) {
  const parsed = Number.parseInt(url.searchParams.get('wait_ms') ?? '0', 10);
  if (Number.isNaN(parsed) || parsed <= 0) return 0;
  return Math.min(parsed, 30000);
}

export function createJsonRpcHttpHandler({
  runtime,
  dispatcher = null,
  mcpDispatcher = null,
  mcpStatelessDispatcher = null,
  mcp = null,
  mcpStateless = null,
  allowedOrigins = [],
  sessionId = makeId('session')
} = {}) {
  if (!Array.isArray(allowedOrigins) || allowedOrigins.some((origin) => {
    try {
      const parsed = new URL(origin);
      return parsed.origin !== origin || !['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return true;
    }
  })) {
    throw new TypeError('allowedOrigins must be an array of complete HTTP origins');
  }
  const permittedOrigins = new Set(allowedOrigins);
  const activeDispatcher = dispatcher ?? createHcpJsonRpcDispatcher(runtime);
  const activeMcpDispatcher = mcpDispatcher ?? createMcpClientShimDispatcher(runtime, mcp ?? {});
  const activeMcpStatelessDispatcher = mcpStatelessDispatcher ?? createMcpClientShimDispatcher(runtime, {
    ...(mcp ?? {}),
    ...(mcpStateless ?? {}),
    protocolVersion: MCP_STATELESS_PROTOCOL_VERSION,
    supportedProtocolVersions: MCP_SUPPORTED_PROTOCOL_VERSIONS
  });
  const baseHeaders = {
    'hcp-session-id': sessionId,
    'hcp-protocol-version': activeDispatcher.protocolVersion
  };
  const mcpHeaders = {
    'mcp-session-id': sessionId,
    'mcp-protocol-version': activeMcpDispatcher.protocolVersion
  };
  const statelessMcpHeaders = {
    'mcp-protocol-version': MCP_STATELESS_PROTOCOL_VERSION
  };

  return function handleHttp(request, response) {
    const currentProtocol = getHeader(request, 'mcp-protocol-version') === MCP_STATELESS_PROTOCOL_VERSION;
    return withAuditAttempt(runtime, {
      principal: (currentProtocol ? (mcpStateless?.principal ?? mcp?.principal) : mcp?.principal) ?? null,
      method: `http.${request.method}`
    }, () => handleHttpInAttempt(request, response));
  };

  async function handleHttpInAttempt(request, response) {
    const url = new URL(request.url, 'http://127.0.0.1');

    try {
      if (!allowedRequestOrigin(request, permittedOrigins)) {
        writeError(response, 403, 'INVALID_ORIGIN', 'Origin is not allowed');
        return;
      }
      if (request.method === 'POST' && url.pathname === '/hcp') {
        if (rejectSessionMismatch(request, response, {
          expected: sessionId,
          headers: baseHeaders
        })) {
          return;
        }
        if (rejectVersionMismatch(request, response, {
          header: 'hcp-protocol-version',
          expected: activeDispatcher.protocolVersion,
          headers: baseHeaders
        })) {
          return;
        }
        const rawBody = await readBody(request);
        const payload = rawBody.length > 0 ? rawBody : '{}';
        const result = await activeDispatcher.handleJson(payload);
        if (result === null) {
          writeEmpty(response, 204, baseHeaders);
          return;
        }
        writeJson(response, 200, result, baseHeaders);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/mcp') {
        const requestedMcpVersion = getHeader(request, 'mcp-protocol-version');
        if (requestedMcpVersion === MCP_STATELESS_PROTOCOL_VERSION) {
          const rawBody = await readBody(request);
          let payload;
          try {
            payload = rawBody.length > 0 ? JSON.parse(rawBody) : {};
          } catch (error) {
            writeMcpJsonRpcError(response, 400, null, -32700, 'PARSE_ERROR', {
              message: error.message
            }, statelessMcpHeaders);
            return;
          }
          if (!validateStatelessMcpHttpRequest(request, response, payload, statelessMcpHeaders)) {
            return;
          }
          const result = await activeMcpStatelessDispatcher.handleJson(payload);
          if (result === null) {
            writeEmpty(response, 202, statelessMcpHeaders);
            return;
          }
          const statusCode = result.error?.code === -32601
            ? 404
            : [-32602, -32021].includes(result.error?.code) ? 400 : 200;
          writeJson(response, statusCode, result, statelessMcpHeaders);
          return;
        }
        if (rejectSessionMismatch(request, response, {
          expected: sessionId,
          headers: mcpHeaders,
          header: 'mcp-session-id',
          aliases: ['hcp-session-id']
        })) {
          return;
        }
        if (rejectVersionMismatch(request, response, {
          header: 'mcp-protocol-version',
          expected: activeMcpDispatcher.protocolVersion,
          headers: mcpHeaders
        })) {
          return;
        }
        const rawBody = await readBody(request);
        const payload = rawBody.length > 0 ? rawBody : '{}';
        const result = await activeMcpDispatcher.handleJson(payload);
        if (result === null) {
          writeEmpty(response, 204, mcpHeaders);
          return;
        }
        writeJson(response, 200, result, mcpHeaders);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/mcp') {
        if (getHeader(request, 'mcp-protocol-version') === MCP_STATELESS_PROTOCOL_VERSION) {
          writeMcpJsonRpcError(response, 405, null, -32601, 'METHOD_NOT_FOUND', {
            message: 'The MCP 2026-07-28 reference path does not use a session-bound GET endpoint.'
          }, statelessMcpHeaders);
          return;
        }
        if (rejectSessionMismatch(request, response, {
          expected: sessionId,
          headers: mcpHeaders,
          header: 'mcp-session-id',
          aliases: ['hcp-session-id']
        })) {
          return;
        }
        if (rejectVersionMismatch(request, response, {
          header: 'mcp-protocol-version',
          expected: activeMcpDispatcher.protocolVersion,
          headers: mcpHeaders
        })) {
          return;
        }
        response.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache',
          connection: 'close',
          ...mcpHeaders
        });
        const notifications = typeof activeMcpDispatcher.drainNotifications === 'function'
          ? activeMcpDispatcher.drainNotifications()
          : [];
        if (notifications.length > 0) {
          for (const notification of notifications) {
            response.write(`event: ${notification.method}\n`);
            response.write(`data: ${JSON.stringify(notification)}\n\n`);
          }
        } else {
          response.write('event: hcp.mcp_shim\n');
          response.write(`data: ${JSON.stringify({
            protocolVersion: activeMcpDispatcher.protocolVersion,
            serverInfo: activeMcpDispatcher.serverInfo,
            note: 'minimal MCP-like SSE endpoint snapshot'
          })}\n\n`);
        }
        response.end();
        return;
      }

      if (request.method === 'DELETE' && url.pathname === '/mcp') {
        if (getHeader(request, 'mcp-protocol-version') === MCP_STATELESS_PROTOCOL_VERSION) {
          writeMcpJsonRpcError(response, 405, null, -32601, 'METHOD_NOT_FOUND', {
            message: 'The MCP 2026-07-28 reference path has no session to delete.'
          }, statelessMcpHeaders);
          return;
        }
        if (rejectSessionMismatch(request, response, {
          expected: sessionId,
          headers: mcpHeaders,
          header: 'mcp-session-id',
          aliases: ['hcp-session-id']
        })) {
          return;
        }
        if (rejectVersionMismatch(request, response, {
          header: 'mcp-protocol-version',
          expected: activeMcpDispatcher.protocolVersion,
          headers: mcpHeaders
        })) {
          return;
        }
        writeEmpty(response, 204, mcpHeaders);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/hcp/events') {
        if (rejectSessionMismatch(request, response, {
          expected: sessionId,
          headers: baseHeaders
        })) {
          return;
        }
        if (rejectVersionMismatch(request, response, {
          header: 'hcp-protocol-version',
          expected: activeDispatcher.protocolVersion,
          headers: baseHeaders
        })) {
          return;
        }
        const taskId = url.searchParams.get('task_id');
        if (!taskId) {
          writeError(response, 400, 'INVALID_INPUT', 'task_id is required', baseHeaders);
          return;
        }

        const events = await runtime.taskWatchWait(taskId, parseSinceEvent(request, url), {
          wait_ms: parseWaitMs(url)
        });
        response.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache',
          connection: 'close',
          ...baseHeaders
        });
        for (const event of events) {
          response.write(`id: ${event.event}\n`);
          response.write(`event: ${event.type}\n`);
          response.write(`data: ${JSON.stringify(event)}\n\n`);
        }
        response.end();
        return;
      }

      if (request.method === 'DELETE' && url.pathname === '/hcp/session') {
        if (rejectSessionMismatch(request, response, {
          expected: sessionId,
          headers: baseHeaders
        })) {
          return;
        }
        if (rejectVersionMismatch(request, response, {
          header: 'hcp-protocol-version',
          expected: activeDispatcher.protocolVersion,
          headers: baseHeaders
        })) {
          return;
        }
        writeEmpty(response, 204, baseHeaders);
        return;
      }

      writeError(response, 404, 'NOT_FOUND', `Unknown HCP HTTP route: ${request.method} ${url.pathname}`, baseHeaders);
    } catch (error) {
      if (error instanceof HcpError) {
        writeJson(response, 400, {
          error: {
            code: error.code,
            message: error.message,
            details: error.details
          }
        }, baseHeaders);
        return;
      }
      writeJson(response, 500, {
        error: {
          code: 'INTERNAL_ERROR',
          message: error?.message ?? String(error)
        }
      }, baseHeaders);
    }
  }
}

export function serveJsonRpcHttp({
  runtime,
  dispatcher = null,
  mcpDispatcher = null,
  mcpStatelessDispatcher = null,
  mcp = null,
  mcpStateless = null,
  allowedOrigins = [],
  host = '127.0.0.1',
  port = 0
} = {}) {
  const handler = createJsonRpcHttpHandler({
    runtime,
    dispatcher,
    mcpDispatcher,
    mcpStatelessDispatcher,
    mcp,
    mcpStateless,
    allowedOrigins
  });
  const server = http.createServer((request, response) => {
    handler(request, response);
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      const address = server.address();
      const origin = `http://${address.address}:${address.port}`;
      resolve({
        server,
        origin,
        close: () => new Promise((closeResolve, closeReject) => {
          server.close((error) => (error ? closeReject(error) : closeResolve()));
        })
      });
    });
  });
}
