import { withAuditAttempt, auditRequestDenial } from './audit-context.js';
import { spawn } from 'node:child_process';
import { HcpError, InvalidInputError, InvalidParamsError } from './errors.js';

const JSONRPC_VERSION = '2.0';
const DEFAULT_PROTOCOL_VERSION = '0.4-draft';

const ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  HCP_ERROR: -32010
};

export const METHOD_PARAM_RULES = {
  'hcp.initialize': {
    protocol_version: { required: true, types: ['string'] },
    client: { types: ['object'] },
    capabilities: { types: ['object'] }
  },
  'hcp.initialized': {},
  'hcp.shutdown': {
    reason: { types: ['string', 'null'] }
  },
  'cap.search': {
    query: { types: ['string'] },
    constraints: { types: ['object'] }
  },
  'cap.describe': {
    capability_id: { required: true, types: ['string'] },
    detail_level: { types: ['string'] }
  },
  'cap.list': {
    filter: { types: ['object'] },
    limit: { types: ['integer'] }
  },
  'task.start': {
    capability_id: { required: true, types: ['string'] },
    input: { types: ['object'] },
    options: { types: ['object'] }
  },
  'task.list': {
    filter: { types: ['object'] },
    options: { types: ['object'] }
  },
  'task.watch': {
    task_id: { required: true, types: ['string'] },
    since_event: { types: ['integer'] },
    wait_ms: { types: ['integer'] }
  },
  'task.result': {
    task_id: { required: true, types: ['string'] },
    projection: { types: ['object'] },
    options: { types: ['object'] }
  },
  'task.approve': {
    task_id: { required: true, types: ['string'] },
    approval: { required: true, types: ['object'] }
  },
  'task.cancel': {
    task_id: { required: true, types: ['string'] },
    reason: { types: ['string'] }
  },
  'task.progress': {
    task_id: { required: true, types: ['string'] },
    progress: { required: true, types: ['object'] }
  },
  'resource.resolve': {
    capability_id: { required: true, types: ['string'] },
    input: { types: ['object'] },
    options: { types: ['object'] }
  },
  'data.peek': {
    handle: { required: true, types: ['string'] },
    projection: { types: ['object'] },
    options: { types: ['object'] }
  },
  'data.pipe': {
    source_handle: { required: true, types: ['string'] },
    target_capability: { required: true, types: ['string'] },
    mapping: { required: true, types: ['object'] },
    options: { types: ['object'] }
  },
  'data.revoke': {
    handle: { required: true, types: ['string'] },
    reason: { types: ['string'] }
  },
  'data.describe': {
    handle: { required: true, types: ['string'] },
    options: { types: ['object'] }
  },
  'grant.create': {
    input: { required: true, types: ['object'] }
  },
  'grant.revoke': {
    grant_id: { required: true, types: ['string'] },
    reason: { types: ['string'] }
  },
  'grant.list': {
    filter: { types: ['object'] },
    options: { types: ['object'] }
  },
  'inspect.runtime': {},
  'inspect.provider': {
    provider_id: { types: ['string', 'null'] }
  },
  'provider.health': {
    provider_id: { required: true, types: ['string'] }
  },
  'provider.register': {
    manifest: { required: true, types: ['object'] },
    options: { types: ['object'] }
  },
  'provider.verify': {
    provider_id: { required: true, types: ['string'] }
  },
  'provider.reload': {
    provider_id: { required: true, types: ['string'] }
  },
  'provider.quarantine': {
    provider_id: { required: true, types: ['string'] },
    reason: { types: ['string'] }
  },
  'policy.explain': {
    capability_id: { required: true, types: ['string'] },
    input: { types: ['object'] },
    options: { types: ['object'] },
    operation: { types: ['string'] }
  },
  'policy.decide': {
    request: { required: true, types: ['object'] }
  },
  'root.add': {
    input: { required: true, types: ['object'] },
    options: { types: ['object'] }
  },
  'root.list': {
    filter: { types: ['object'] },
    options: { types: ['object'] }
  },
  'root.remove': {
    root_id: { required: true, types: ['string'] },
    options: { types: ['object'] }
  },
  'approval.request': {
    action_summary: { required: true, types: ['string'] },
    risk: { required: true, types: ['string'] },
    options: { types: ['object'] }
  },
  'input.request': {
    schema: { required: true, types: ['object'] },
    prompt: { required: true, types: ['string'] },
    options: { types: ['object'] }
  },
  'model.request': {
    request: { required: true, types: ['object'] },
    options: { types: ['object'] }
  },
  'audit.get_trace': {
    trace_id: { types: ['string'] },
    task_id: { types: ['string'] }
  },
  'audit.search': {
    filter: { types: ['object'] }
  },
  'audit.export': {
    filter: { types: ['object'] }
  }
};

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasId(message) {
  return Object.prototype.hasOwnProperty.call(message, 'id');
}

function jsonRpcError(id, code, message, data = undefined) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    error
  };
}

function jsonRpcResult(id, result) {
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    result
  };
}

function toJsonRpcError(id, error) {
  if (error instanceof HcpError) {
    const jsonRpcCode = error.code === 'METHOD_NOT_FOUND'
      ? ERROR_CODES.METHOD_NOT_FOUND
      : error.code === 'INVALID_PARAMS'
        ? ERROR_CODES.INVALID_PARAMS
        : ERROR_CODES.HCP_ERROR;
    return jsonRpcError(id, jsonRpcCode, error.code, {
      hcp_code: error.code,
      message: error.message,
      details: error.details ?? {}
    });
  }

  return jsonRpcError(id, ERROR_CODES.INTERNAL_ERROR, 'INTERNAL_ERROR', {
    message: error?.message ?? String(error)
  });
}

function requireParams(params) {
  if (params === undefined) return {};
  if (!isObject(params)) {
    throw new InvalidParamsError('JSON-RPC params must be an object', { params });
  }
  return params;
}

function typeOfParam(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

function validateMethodParams(method, params) {
  const rules = METHOD_PARAM_RULES[method];
  if (!rules) return;

  for (const [name, rule] of Object.entries(rules)) {
    const exists = Object.prototype.hasOwnProperty.call(params, name);
    if (rule.required && (!exists || params[name] === undefined)) {
      throw new InvalidParamsError(`Missing required JSON-RPC param: ${name}`, {
        method,
        param: name,
        reason: 'MISSING_REQUIRED_PARAM'
      });
    }
    if (!exists || params[name] === undefined) continue;

    const actualType = typeOfParam(params[name]);
    if (!rule.types.includes(actualType)) {
      throw new InvalidParamsError(`Invalid JSON-RPC param type for ${name}`, {
        method,
        param: name,
        expected: rule.types,
        received: actualType,
        reason: 'INVALID_PARAM_TYPE'
      });
    }
  }
}

export class HcpJsonRpcClient {
  constructor({ transport, idPrefix = 'req', protocolVersion = DEFAULT_PROTOCOL_VERSION, autoInitialize = true } = {}) {
    if (!transport || typeof transport.request !== 'function') {
      throw new InvalidInputError('JSON-RPC client transport must implement request(message)', { transport });
    }
    this.transport = transport;
    this.idPrefix = idPrefix;
    this.nextId = 1;
    this.protocolVersion = protocolVersion;
    this.autoInitialize = autoInitialize;
    this.hasInitialized = false;
    this.initializing = null;
  }

  async request(method, params = {}) {
    const response = await this.rawRequest(method, params);
    if (response?.error) {
      const data = response.error.data ?? {};
      throw new HcpError(response.error.message, data.hcp_code ?? 'JSONRPC_ERROR', {
        jsonrpc_code: response.error.code,
        data
      });
    }
    return response?.result;
  }

  async rawRequest(method, params = {}) {
    if (this.autoInitialize && !this.hasInitialized && !this.#isInitializationMethod(method)) {
      await this.#ensureInitialized();
    }
    const id = `${this.idPrefix}_${this.nextId++}`;
    const response = await this.transport.request({
      jsonrpc: JSONRPC_VERSION,
      id,
      method,
      params
    });
    if (method === 'hcp.initialize' && !response?.error) {
      this.hasInitialized = true;
    }
    return response;
  }

  async notify(method, params = {}) {
    if (typeof this.transport.notify === 'function') {
      return this.transport.notify({
        jsonrpc: JSONRPC_VERSION,
        method,
        params
      });
    }
    return this.transport.request({
      jsonrpc: JSONRPC_VERSION,
      method,
      params
    });
  }

  #isInitializationMethod(method) {
    return method === 'hcp.initialize' || method === 'hcp.initialized' || method === 'hcp.shutdown';
  }

  async #ensureInitialized() {
    if (!this.initializing) {
      this.initializing = this.rawRequest('hcp.initialize', { protocol_version: this.protocolVersion })
        .finally(() => {
          this.initializing = null;
        });
    }
    await this.initializing;
  }

  initialize(params = {}) {
    return this.request('hcp.initialize', params);
  }

  initialized(params = {}) {
    return this.notify('hcp.initialized', params);
  }

  shutdown(reason = null) {
    return this.request('hcp.shutdown', { reason });
  }

  capSearch(query, constraints = {}) {
    return this.request('cap.search', { query, constraints });
  }

  capDescribe(capabilityId, detailLevel = 'summary') {
    return this.request('cap.describe', { capability_id: capabilityId, detail_level: detailLevel });
  }

  capList(filter = {}, limit = 100) {
    return this.request('cap.list', { filter, limit });
  }

  taskStart(capabilityId, input = {}, options = {}) {
    return this.request('task.start', { capability_id: capabilityId, input, options });
  }

  taskList(filter = {}, options = {}) {
    return this.request('task.list', { filter, options });
  }

  taskWatch(taskId, sinceEvent = 0, options = {}) {
    return this.request('task.watch', { task_id: taskId, since_event: sinceEvent, ...options });
  }

  taskResult(taskId, projection = {}, options = {}) {
    return this.request('task.result', { task_id: taskId, projection, options });
  }

  taskApprove(taskId, approval = { approved: true }) {
    return this.request('task.approve', { task_id: taskId, approval });
  }

  taskCancel(taskId, reason = 'cancelled') {
    return this.request('task.cancel', { task_id: taskId, reason });
  }

  taskProgress(taskId, progress = {}) {
    return this.request('task.progress', { task_id: taskId, progress });
  }

  resourceResolve(capabilityId, input = {}, options = {}) {
    return this.request('resource.resolve', { capability_id: capabilityId, input, options });
  }

  dataPeek(handle, projection = {}, options = {}) {
    return this.request('data.peek', { handle, projection, options });
  }

  dataRevoke(handle, reason = 'revoked') {
    return this.request('data.revoke', { handle, reason });
  }

  dataDescribe(handle, options = {}) {
    return this.request('data.describe', { handle, options });
  }

  dataPipe(sourceHandle, targetCapability, mapping = {}, options = {}) {
    return this.request('data.pipe', {
      source_handle: sourceHandle,
      target_capability: targetCapability,
      mapping,
      options
    });
  }

  grantCreate(input = {}) {
    return this.request('grant.create', { input });
  }

  grantRevoke(grantId, reason = 'revoked') {
    return this.request('grant.revoke', { grant_id: grantId, reason });
  }

  grantList(filter = {}, options = {}) {
    return this.request('grant.list', { filter, options });
  }

  inspectRuntime() {
    return this.request('inspect.runtime');
  }

  inspectProvider(providerId = null) {
    return this.request('inspect.provider', { provider_id: providerId });
  }

  providerHealth(providerId) {
    return this.request('provider.health', { provider_id: providerId });
  }

  providerRegister(manifest, options = {}) {
    return this.request('provider.register', { manifest, options });
  }

  providerVerify(providerId) {
    return this.request('provider.verify', { provider_id: providerId });
  }

  providerReload(providerId) {
    return this.request('provider.reload', { provider_id: providerId });
  }

  providerQuarantine(providerId, reason = 'quarantined') {
    return this.request('provider.quarantine', { provider_id: providerId, reason });
  }

  policyExplain(capabilityId, input = {}, options = {}, operation = 'invoke') {
    return this.request('policy.explain', {
      capability_id: capabilityId,
      input,
      options,
      operation
    });
  }

  policyDecide(request = {}) {
    return this.request('policy.decide', { request });
  }

  rootAdd(input = {}, options = {}) {
    return this.request('root.add', { input, options });
  }

  rootList(filter = {}, options = {}) {
    return this.request('root.list', { filter, options });
  }

  rootRemove(rootId, options = {}) {
    return this.request('root.remove', { root_id: rootId, options });
  }

  approvalRequest(actionSummary, risk = 'medium', options = {}) {
    return this.request('approval.request', { action_summary: actionSummary, risk, options });
  }

  inputRequest(schema = {}, prompt = '', options = {}) {
    return this.request('input.request', { schema, prompt, options });
  }

  modelRequest(request = {}, options = {}) {
    return this.request('model.request', { request, options });
  }

  auditGetTrace(taskId) {
    return this.request('audit.get_trace', { task_id: taskId });
  }

  auditSearch(filter = {}) {
    return this.request('audit.search', { filter });
  }

  auditExport(filter = {}) {
    return this.request('audit.export', { filter });
  }
}

export function createInMemoryJsonRpcTransport(dispatcher) {
  return {
    request(message) {
      return dispatcher.handleJson(message);
    },
    notify(message) {
      return dispatcher.handleJson(message);
    }
  };
}

export function createHttpJsonRpcTransport({
  origin,
  path = '/hcp',
  fetchImpl = globalThis.fetch,
  headers = {}
} = {}) {
  if (!origin || typeof origin !== 'string') {
    throw new InvalidInputError('HTTP JSON-RPC transport requires origin', { origin });
  }
  if (typeof fetchImpl !== 'function') {
    throw new InvalidInputError('HTTP JSON-RPC transport requires fetch implementation', { fetchImpl });
  }
  const endpoint = new URL(path, origin.endsWith('/') ? origin : `${origin}/`).toString();

  async function send(message) {
    const response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...headers
      },
      body: JSON.stringify(message)
    });

    if (response.status === 204) return null;
    const text = await response.text();
    const payload = text.length > 0 ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new HcpError(`HTTP JSON-RPC request failed with status ${response.status}`, 'HTTP_TRANSPORT_ERROR', {
        status: response.status,
        body: payload
      });
    }
    return payload;
  }

  return {
    request: send,
    notify: send
  };
}

export function createStdioJsonRpcTransport({
  command,
  args = [],
  cwd = process.cwd(),
  env = undefined,
  timeoutMs = 5000,
  spawnImpl = spawn
} = {}) {
  if (!command || typeof command !== 'string') {
    throw new InvalidInputError('Stdio JSON-RPC transport requires command', { command });
  }
  if (!Array.isArray(args)) {
    throw new InvalidInputError('Stdio JSON-RPC transport args must be an array', { args });
  }
  if (typeof spawnImpl !== 'function') {
    throw new InvalidInputError('Stdio JSON-RPC transport requires spawn implementation', { spawnImpl });
  }

  const child = spawnImpl(command, args, {
    cwd,
    ...(env ? { env: { ...process.env, ...env } } : {}),
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  const pending = new Map();
  let stdoutBuffer = '';
  let stderrBuffer = '';
  let closed = false;
  let closePromise = null;

  function failPending(error) {
    for (const { reject, timer } of pending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    pending.clear();
  }

  function transportError(message, details = {}) {
    return new HcpError(message, 'STDIO_TRANSPORT_ERROR', {
      stderr: stderrBuffer,
      ...details
    });
  }

  function handleResponseLine(rawLine) {
    const line = rawLine.trim();
    if (!line) return;

    let response;
    try {
      response = JSON.parse(line);
    } catch (error) {
      failPending(transportError('Stdio JSON-RPC transport received invalid JSON', {
        line,
        parse_error: error.message
      }));
      return;
    }

    const key = String(response.id);
    const entry = pending.get(key);
    if (!entry) return;
    pending.delete(key);
    clearTimeout(entry.timer);
    entry.resolve(response);
  }

  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk.toString('utf8');
    let newlineIndex = stdoutBuffer.indexOf('\n');
    while (newlineIndex >= 0) {
      const rawLine = stdoutBuffer.slice(0, newlineIndex).replace(/\r$/, '');
      stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
      handleResponseLine(rawLine);
      newlineIndex = stdoutBuffer.indexOf('\n');
    }
  });

  child.stderr.on('data', (chunk) => {
    stderrBuffer += chunk.toString('utf8');
  });

  child.on('error', (error) => {
    failPending(transportError('Stdio JSON-RPC transport process error', {
      message: error.message
    }));
  });

  child.on('close', (code, signal) => {
    closed = true;
    if (pending.size > 0) {
      failPending(transportError('Stdio JSON-RPC transport closed before all responses arrived', {
        exit_code: code,
        signal
      }));
    }
  });

  function writeMessage(message) {
    if (closed || child.stdin.destroyed) {
      throw transportError('Stdio JSON-RPC transport is closed');
    }
    child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  return {
    request(message) {
      if (!Object.prototype.hasOwnProperty.call(message ?? {}, 'id')) {
        throw new InvalidInputError('Stdio JSON-RPC request message must include id', { message });
      }
      const key = String(message.id);
      if (pending.has(key)) {
        throw new InvalidInputError('Duplicate JSON-RPC request id', { id: message.id });
      }

      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(key);
          reject(transportError(`Timed out waiting for stdio JSON-RPC response after ${timeoutMs}ms`, {
            id: message.id,
            timeout_ms: timeoutMs
          }));
        }, timeoutMs);
        pending.set(key, { resolve, reject, timer });

        try {
          writeMessage(message);
        } catch (error) {
          clearTimeout(timer);
          pending.delete(key);
          reject(error);
        }
      });
    },

    async notify(message) {
      writeMessage(message);
      return null;
    },

    close({ killAfterMs = 1000 } = {}) {
      if (closePromise) return closePromise;
      closePromise = new Promise((resolve) => {
        if (closed) {
          resolve({ exit_code: child.exitCode, stderr: stderrBuffer });
          return;
        }

        const timer = setTimeout(() => {
          if (!closed) child.kill();
        }, killAfterMs);

        child.once('close', (code, signal) => {
          clearTimeout(timer);
          resolve({ exit_code: code, signal, stderr: stderrBuffer });
        });

        child.stdin.end();
      });
      return closePromise;
    }
  };
}

export class HcpJsonRpcDispatcher {
  constructor(runtime, { protocolVersion = DEFAULT_PROTOCOL_VERSION, runtimeInfo = {}, requireInitialize = true } = {}) {
    this.runtime = runtime;
    this.protocolVersion = protocolVersion;
    this.requireInitialize = requireInitialize;
    this.runtimeInfo = {
      name: 'hcp-runtime-prototype',
      version: '0.3.0',
      ...runtimeInfo
    };
    this.handshakeAccepted = false;
    this.initialized = false;
  }

  async handleJson(raw) {
    let message;
    try {
      message = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch (error) {
      return jsonRpcError(null, ERROR_CODES.PARSE_ERROR, 'PARSE_ERROR', {
        message: error.message
      });
    }

    if (Array.isArray(message)) {
      if (message.length === 0) {
        return jsonRpcError(null, ERROR_CODES.INVALID_REQUEST, 'INVALID_REQUEST');
      }
      const responses = [];
      for (const item of message) {
        const response = await this.handleMessage(item);
        if (response !== null) responses.push(response);
      }
      return responses.length > 0 ? responses : null;
    }

    return this.handleMessage(message);
  }

  handleMessage(message) {
    return withAuditAttempt(this.runtime, { method: message?.method ?? 'unknown', request_id: message?.id ?? null }, () => this.handleMessageInAttempt(message));
  }

  async handleMessageInAttempt(message) {
    if (!isObject(message) || message.jsonrpc !== JSONRPC_VERSION || typeof message.method !== 'string') {
      return jsonRpcError(hasId(message ?? {}) ? message.id : null, ERROR_CODES.INVALID_REQUEST, 'INVALID_REQUEST');
    }

    const id = hasId(message) ? message.id : null;
    const isNotification = !hasId(message);

    try {
      if (this.requireInitialize && !this.handshakeAccepted && !this.#isInitializationMethod(message.method)) {
        throw new HcpError('Call hcp.initialize before normal protocol methods', 'INITIALIZATION_REQUIRED', {
          method: message.method
        });
      }
      const params = requireParams(message.params);
      validateMethodParams(message.method, params);
      const result = await this.#dispatch(message.method, params);
      return isNotification ? null : jsonRpcResult(id, result);
    } catch (error) {
      auditRequestDenial(error.code ?? 'INTERNAL_ERROR');
      if (isNotification) return null;
      return toJsonRpcError(id, error);
    }
  }

  async #dispatch(method, params) {
    switch (method) {
      case 'hcp.initialize':
        return this.#initialize(params);
      case 'hcp.initialized':
        this.initialized = true;
        return { acknowledged: true };
      case 'hcp.shutdown':
        return { shutting_down: true, reason: params.reason ?? null };
      case 'cap.search':
        return this.runtime.capSearch(params.query ?? '', params.constraints ?? {});
      case 'cap.describe':
        return this.runtime.capDescribe(params.capability_id, params.detail_level ?? 'summary');
      case 'cap.list':
        return this.runtime.capSearch(params.query ?? '', { ...(params.filter ?? {}), limit: params.limit ?? 100 });
      case 'task.start':
        return this.runtime.taskStart(params.capability_id, params.input ?? {}, params.options ?? {});
      case 'task.list':
        return this.runtime.taskList(params.filter ?? {}, params.options ?? {});
      case 'task.watch':
        if (params.wait_ms) {
          return this.runtime.taskWatchWait(params.task_id, params.since_event ?? 0, {
            wait_ms: params.wait_ms
          });
        }
        return this.runtime.taskWatch(params.task_id, params.since_event ?? 0);
      case 'task.result':
        return this.runtime.taskResult(params.task_id, params.projection ?? {}, params.options ?? {});
      case 'task.approve':
        return this.runtime.taskApprove(params.task_id, params.approval ?? { approved: true });
      case 'task.cancel':
        return this.runtime.taskCancel(params.task_id, params.reason ?? 'cancelled');
      case 'task.progress':
        return this.runtime.taskProgress(params.task_id, params.progress ?? {});
      case 'resource.resolve':
        return this.runtime.resourceResolve(params.capability_id, params.input ?? {}, params.options ?? {});
      case 'data.peek':
        return this.runtime.dataPeek(params.handle, params.projection ?? {}, params.options ?? {});
      case 'data.pipe':
        return this.runtime.dataPipe(params.source_handle, params.target_capability, params.mapping ?? {}, params.options ?? {});
      case 'data.revoke':
        return this.runtime.dataRevoke(params.handle, params.reason ?? 'revoked');
      case 'data.describe':
        return this.runtime.dataDescribe(params.handle, params.options ?? {});
      case 'grant.create':
        return this.runtime.grantCreate(params.input ?? params);
      case 'grant.revoke':
        return this.runtime.grantRevoke(params.grant_id, params.reason ?? 'revoked');
      case 'grant.list':
        return this.runtime.grantList(params.filter ?? {}, params.options ?? {});
      case 'inspect.runtime':
        return this.runtime.inspectRuntime();
      case 'inspect.provider':
        return this.runtime.inspectProvider(params.provider_id ?? null);
      case 'provider.health':
        return this.runtime.providerHealth(params.provider_id);
      case 'provider.register':
        return this.runtime.providerRegister(params.manifest, params.options ?? {});
      case 'provider.verify':
        return this.runtime.providerVerify(params.provider_id);
      case 'provider.reload':
        return this.runtime.providerReload(params.provider_id);
      case 'provider.quarantine':
        return this.runtime.providerQuarantine(params.provider_id, params.reason ?? 'quarantined');
      case 'policy.explain':
        return this.runtime.policyExplain(params.capability_id, params.input ?? {}, params.options ?? {}, {
          operation: params.operation ?? 'invoke'
        });
      case 'policy.decide': {
        const request = params.request ?? {};
        return this.runtime.policyExplain(request.capability_id, request.input ?? {}, request.options ?? {}, {
          operation: request.operation ?? 'invoke'
        });
      }
      case 'root.add':
        return this.runtime.rootAdd(params.input ?? {}, params.options ?? {});
      case 'root.list':
        return this.runtime.rootList(params.filter ?? {}, params.options ?? {});
      case 'root.remove':
        return this.runtime.rootRemove(params.root_id, params.options ?? {});
      case 'approval.request':
        return this.runtime.approvalRequest(params.action_summary, params.risk ?? 'medium', params.options ?? {});
      case 'input.request':
        return this.runtime.inputRequest(params.schema ?? {}, params.prompt ?? '', params.options ?? {});
      case 'model.request':
        return this.runtime.modelRequest(params.request ?? {}, params.options ?? {});
      case 'audit.get_trace':
        return this.runtime.auditGetTrace(params.trace_id ?? params.task_id);
      case 'audit.search':
        return this.runtime.auditSearch(params.filter ?? {});
      case 'audit.export':
        return this.runtime.auditExport(params.filter ?? {});
      default:
        throw new HcpError(`Unknown JSON-RPC method: ${method}`, 'METHOD_NOT_FOUND', { method });
    }
  }

  #isInitializationMethod(method) {
    return method === 'hcp.initialize' || method === 'hcp.initialized' || method === 'hcp.shutdown';
  }

  #initialize(params) {
    const clientVersion = params.protocol_version ?? this.protocolVersion;
    const supported = clientVersion === this.protocolVersion;
    if (!supported) {
      throw new HcpError('Protocol version mismatch', 'PROTOCOL_VERSION_MISMATCH', {
        expected: this.protocolVersion,
        received: clientVersion
      });
    }
    this.handshakeAccepted = true;
    this.initialized = false;
    return {
      protocol_version: this.protocolVersion,
      negotiated: true,
      runtime: this.runtimeInfo,
      capabilities: {
        task_events: true,
        data_handles: true,
        data_pipe: true,
        audit_trace: true,
        cancellation: true,
        progress: true,
        model_request_records: true,
        provider_management: true,
        mcp_compat: false
      }
    };
  }
}

export function createHcpJsonRpcDispatcher(runtime, options = {}) {
  return new HcpJsonRpcDispatcher(runtime, options);
}
