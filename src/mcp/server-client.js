import { HcpError, InvalidInputError } from '../errors.js';
import { createStdioJsonRpcTransport } from '../jsonrpc.js';
import {
  JSONRPC_VERSION,
  MCP_PROTOCOL_VERSION,
  isMethodNotFound,
  isObject,
  isStatelessMcpProtocolVersion,
  toMcpClientError,
  withStatelessRequestMeta
} from './common.js';

export function createMcpJsonRpcServerClient({
  transport,
  protocolVersion = MCP_PROTOCOL_VERSION,
  clientInfo = { name: 'hcp-mcp-jsonrpc-adapter', version: '0.1.0' },
  clientCapabilities = {},
  logLevel = undefined,
  autoInitialize = true,
  idPrefix = 'mcp'
} = {}) {
  if (!transport || typeof transport.request !== 'function') {
    throw new InvalidInputError('MCP JSON-RPC server client requires transport.request(message)', { transport });
  }

  let nextId = 1;
  let initialized = false;
  let initializing = null;
  const stateless = isStatelessMcpProtocolVersion(protocolVersion);

  function requestParams(params) {
    if (!stateless) return params;
    return withStatelessRequestMeta(params, {
      protocolVersion,
      clientInfo,
      clientCapabilities,
      logLevel
    });
  }

  async function rawRequest(method, params = {}) {
    if (autoInitialize && !initialized && !stateless && method !== 'initialize' && method !== 'notifications/initialized') {
      await ensureInitialized();
    }
    const response = await transport.request({
      jsonrpc: JSONRPC_VERSION,
      id: `${idPrefix}_${nextId++}`,
      method,
      params: requestParams(params)
    });
    if (method === 'initialize' && !response?.error) initialized = true;
    return response;
  }

  async function request(method, params = {}) {
    const response = await rawRequest(method, params);
    if (response?.error) throw toMcpClientError(response);
    return response?.result ?? {};
  }

  async function optionalList(method, field) {
    try {
      const result = await request(method, {});
      return Array.isArray(result[field]) ? result[field] : [];
    } catch (error) {
      if (isMethodNotFound(error)) return [];
      throw error;
    }
  }

  async function ensureInitialized() {
    if (initialized) return;
    if (!initializing) {
      initializing = (stateless
        ? request('server/discover', {})
        : request('initialize', { protocolVersion, clientInfo }))
        .then(async (result) => {
          if (stateless && !result.supportedVersions?.includes(protocolVersion)) {
            throw new HcpError('MCP server discovery did not advertise the requested protocol version', 'PROTOCOL_VERSION_MISMATCH', {
              expected: protocolVersion,
              supported: result.supportedVersions ?? []
            });
          }
          if (!stateless && result.protocolVersion && result.protocolVersion !== protocolVersion) {
            throw new HcpError('MCP server negotiated an unexpected protocol version', 'PROTOCOL_VERSION_MISMATCH', {
              expected: protocolVersion,
              received: result.protocolVersion
            });
          }
          if (!stateless && typeof transport.notify === 'function') {
            await transport.notify({
              jsonrpc: JSONRPC_VERSION,
              method: 'notifications/initialized',
              params: {}
            });
          }
          initialized = true;
          return result;
        })
        .finally(() => {
          initializing = null;
        });
    }
    await initializing;
  }

  return {
    protocolVersion,
    clientInfo,
    clientCapabilities,
    stateless,

    get initialized() {
      return initialized;
    },

    initialize: ensureInitialized,

    async discover() {
      if (!stateless) {
        throw new HcpError('server/discover is only available through the MCP 2026-07-28 stateless path', 'METHOD_NOT_FOUND', {
          protocolVersion
        });
      }
      const result = await request('server/discover', {});
      initialized = true;
      return result;
    },

    async ping() {
      return request('ping', {});
    },

    async listTools() {
      return optionalList('tools/list', 'tools');
    },

    async callTool({ name, arguments: args = {} }) {
      return request('tools/call', { name, arguments: args });
    },

    async listResources() {
      return optionalList('resources/list', 'resources');
    },

    async listResourceTemplates() {
      return optionalList('resources/templates/list', 'resourceTemplates');
    },

    async readResource({ uri }) {
      return request('resources/read', { uri });
    },

    async listPrompts() {
      return optionalList('prompts/list', 'prompts');
    },

    async getPrompt({ name, arguments: args = {} }) {
      return request('prompts/get', { name, arguments: args });
    },

    async health() {
      await ensureInitialized();
      if (typeof transport.request === 'function') {
        try {
          await request('ping', {});
        } catch (error) {
          if (!isMethodNotFound(error)) throw error;
        }
      }
      return {
        status: 'ok',
        protocol: 'mcp-jsonrpc',
        protocolVersion
      };
    },

    async close() {
      if (typeof transport.close === 'function') {
        return transport.close();
      }
      return { closed: true };
    }
  };
}

export function createMcpStdioServerClient({
  command,
  args = [],
  cwd = process.cwd(),
  env = undefined,
  timeoutMs = 5000,
  transport = null,
  protocolVersion = MCP_PROTOCOL_VERSION,
  clientInfo = { name: 'hcp-mcp-stdio-adapter', version: '0.1.0' },
  clientCapabilities = {},
  logLevel = undefined
} = {}) {
  const activeTransport = transport ?? createStdioJsonRpcTransport({
    command,
    args,
    cwd,
    env,
    timeoutMs
  });
  return createMcpJsonRpcServerClient({
    transport: activeTransport,
    protocolVersion,
    clientInfo,
    clientCapabilities,
    logLevel
  });
}

export function createMcpHttpJsonRpcTransport({
  origin,
  path = '/mcp',
  fetchImpl = globalThis.fetch,
  headers = {},
  protocolVersion = MCP_PROTOCOL_VERSION,
  sessionId = null
} = {}) {
  if (!origin || typeof origin !== 'string') {
    throw new InvalidInputError('MCP HTTP JSON-RPC transport requires origin', { origin });
  }
  if (typeof fetchImpl !== 'function') {
    throw new InvalidInputError('MCP HTTP JSON-RPC transport requires fetch implementation', { fetchImpl });
  }
  const endpoint = new URL(path, origin.endsWith('/') ? origin : `${origin}/`).toString();
  let activeSessionId = sessionId;
  const stateless = isStatelessMcpProtocolVersion(protocolVersion);

  function mcpNameForMessage(message) {
    if (!isObject(message?.params)) return null;
    if (typeof message.params.name === 'string') return message.params.name;
    if (typeof message.params.uri === 'string') return message.params.uri;
    if (typeof message.params.taskId === 'string') return message.params.taskId;
    return null;
  }

  function encodeMirroredName(value) {
    if (value === null) return null;
    if (!/^[\x20-\x7E\t]+$/.test(value) || value.trim() !== value ||
        (value.startsWith('=?base64?') && value.endsWith('?='))) {
      return `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`;
    }
    return value;
  }

  function requestHeaders(message = null) {
    return {
      'content-type': 'application/json',
      ...headers,
      ...(stateless ? { Accept: 'application/json, text/event-stream' } : {}),
      'MCP-Protocol-Version': protocolVersion,
      ...(stateless || !activeSessionId ? {} : { 'MCP-Session-Id': activeSessionId }),
      ...(message?.method ? { 'Mcp-Method': message.method } : {}),
      ...(mcpNameForMessage(message) ? { 'Mcp-Name': encodeMirroredName(mcpNameForMessage(message)) } : {})
    };
  }

  function captureSession(response) {
    if (stateless) return;
    const responseProtocolVersion = response.headers.get('mcp-protocol-version');
    if (responseProtocolVersion && responseProtocolVersion !== protocolVersion) {
      throw new HcpError('MCP HTTP server returned an unexpected protocol version', 'PROTOCOL_VERSION_MISMATCH', {
        expected: protocolVersion,
        received: responseProtocolVersion
      });
    }
    const responseSessionId = response.headers.get('mcp-session-id');
    if (responseSessionId) activeSessionId = responseSessionId;
  }

  async function readSseReply(response, expectedId) {
    if (!response.body) {
      throw new HcpError('MCP SSE response has no body', 'MCP_HTTP_TRANSPORT_ERROR');
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending = '';
    let eventData = [];
    const finishEvent = () => {
      if (eventData.length === 0) return null;
      const data = eventData.join('\n');
      eventData = [];
      const event = JSON.parse(data);
      return event?.jsonrpc === '2.0' && event.id === expectedId ? event : null;
    };
    const consumeLines = (flush = false) => {
      for (;;) {
        const newline = pending.indexOf('\n');
        if (newline < 0 && !flush) return null;
        let line;
        if (newline < 0) {
          line = pending;
          pending = '';
        } else {
          line = pending.slice(0, newline);
          pending = pending.slice(newline + 1);
        }
        if (line.endsWith('\r')) line = line.slice(0, -1);
        if (line === '') {
          const reply = finishEvent();
          if (reply) return reply;
        } else if (line.startsWith('data:')) {
          eventData.push(line.slice(5).replace(/^ /, ''));
        }
        if (newline < 0) return null;
      }
    };
    try {
      for (;;) {
        const { value, done } = await reader.read();
        pending += decoder.decode(value, { stream: !done });
        const reply = consumeLines(done);
        if (reply) return reply;
        if (done) {
          const finalReply = finishEvent();
          if (finalReply) return finalReply;
          throw new HcpError('MCP SSE stream ended without a matching response', 'MCP_HTTP_TRANSPORT_ERROR', {
            id: expectedId
          });
        }
      }
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }

  async function send(message) {
    const response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: requestHeaders(message),
      body: JSON.stringify(message)
    });
    captureSession(response);

    if (response.status === 204 || response.status === 202) return null;
    const payload = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'text/event-stream'
      ? await readSseReply(response, message.id)
      : await response.text().then((text) => text.length > 0 ? JSON.parse(text) : null);
    if (!response.ok) {
      throw new HcpError(`MCP HTTP JSON-RPC request failed with status ${response.status}`, 'MCP_HTTP_TRANSPORT_ERROR', {
        status: response.status,
        body: payload
      });
    }
    return payload;
  }

  return {
    get sessionId() {
      return activeSessionId;
    },
    get stateless() {
      return stateless;
    },
    request: send,
    notify: send,
    async close() {
      if (stateless) return { closed: true, session_id: null, stateless: true };
      if (!activeSessionId) return { closed: true, session_id: null };
      const response = await fetchImpl(endpoint, {
        method: 'DELETE',
        headers: requestHeaders()
      });
      captureSession(response);
      if (!response.ok && response.status !== 204) {
        const text = await response.text();
        const payload = text.length > 0 ? JSON.parse(text) : null;
        throw new HcpError(`MCP HTTP session close failed with status ${response.status}`, 'MCP_HTTP_TRANSPORT_ERROR', {
          status: response.status,
          body: payload
        });
      }
      const closedSessionId = activeSessionId;
      activeSessionId = null;
      return { closed: true, session_id: closedSessionId };
    }
  };
}

export function createMcpHttpServerClient({
  origin,
  path = '/mcp',
  fetchImpl = globalThis.fetch,
  headers = {},
  sessionId = null,
  protocolVersion = MCP_PROTOCOL_VERSION,
  clientInfo = { name: 'hcp-mcp-http-adapter', version: '0.1.0' },
  clientCapabilities = {},
  logLevel = undefined
} = {}) {
  const transport = createMcpHttpJsonRpcTransport({
    origin,
    path,
    fetchImpl,
    headers,
    protocolVersion,
    sessionId
  });
  return createMcpJsonRpcServerClient({
    transport,
    protocolVersion,
    clientInfo,
    clientCapabilities,
    logLevel
  });
}
