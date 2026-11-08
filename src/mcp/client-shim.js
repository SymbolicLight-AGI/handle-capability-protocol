import { withAuditAttempt, auditRequestDenial } from '../audit-context.js';
import { HcpError, InvalidInputError } from '../errors.js';
import {
  JSONRPC_VERSION,
  MCP_JSONRPC_ERRORS,
  MCP_LIST_CHANGED_METHODS,
  MCP_LOG_LEVEL_ORDER,
  MCP_LOG_LEVELS,
  MCP_NOTIFICATION_QUEUE_LIMIT,
  MCP_PROTOCOL_VERSION,
  MCP_STATELESS_REMOVED_METHODS,
  MCP_SUPPORTED_PROTOCOL_VERSIONS,
  hasId,
  isObject,
  isStatelessMcpProtocolVersion,
  mcpJsonRpcError,
  mcpJsonRpcResult,
  mcpListPage,
  mcpServerCapabilities,
  toMcpJsonRpcError,
  toMcpRoot,
  toMcpTask,
  validateStatelessRequestMeta,
  withConservativeCacheHints,
  withStatelessResponseMeta
} from './common.js';
import { createMcpRuntimeFacade } from './runtime-facade.js';

export function createMcpClientShimDispatcher(runtime, {
  principal = null,
  approval = null,
  protocolVersion = MCP_PROTOCOL_VERSION,
  serverInfo = {},
  supportedProtocolVersions = MCP_SUPPORTED_PROTOCOL_VERSIONS,
  scopeDiscovery = false,
  requestStateAuthority = null
} = {}) {
  const facade = createMcpRuntimeFacade(runtime, { principal, approval, scopeDiscovery, requestStateAuthority });
  let logLevel = 'info';
  const stateless = isStatelessMcpProtocolVersion(protocolVersion);
  const supportedVersions = [...new Set(supportedProtocolVersions)];
  if (!supportedVersions.includes(protocolVersion)) supportedVersions.push(protocolVersion);
  let mcpInitialized = stateless;
  let mcpInitializedNotificationReceived = false;
  const resourceSubscriptions = new Set();
  const notificationQueue = [];
  const info = {
    name: 'hcp-runtime-mcp-shim',
    version: '0.1.0',
    ...serverInfo
  };

  function queueNotification(notification, auditEntry) {
    notificationQueue.push(notification);
    while (notificationQueue.length > MCP_NOTIFICATION_QUEUE_LIMIT) {
      notificationQueue.shift();
    }
    runtime.auditEntries.push({
      timestamp: new Date().toISOString(),
      principal,
      protocol: 'mcp',
      shim: info.name,
      ...auditEntry
    });
    return notification;
  }

  function emitListChanged(kind, details = {}) {
    const method = MCP_LIST_CHANGED_METHODS[kind];
    if (!method) {
      throw new InvalidInputError('MCP list_changed kind must be tools, resources, or prompts', {
        kind,
        allowed: Object.keys(MCP_LIST_CHANGED_METHODS)
      });
    }
    const notification = {
      jsonrpc: JSONRPC_VERSION,
      method
    };
    return queueNotification(notification, {
      type: 'MCP_LIST_CHANGED_QUEUED',
      kind,
      method,
      details
    });
  }

  function emitTaskStatus(taskOrTaskId, details = {}) {
    const snapshot = typeof taskOrTaskId === 'string'
      ? runtime.taskSnapshot(taskOrTaskId)
      : taskOrTaskId;
    if (!isObject(snapshot) || typeof snapshot.task_id !== 'string') {
      throw new InvalidInputError('MCP task status notification requires a task snapshot or task id', {
        task: taskOrTaskId
      });
    }
    const task = toMcpTask(snapshot);
    const notification = {
      jsonrpc: JSONRPC_VERSION,
      method: 'notifications/tasks/status',
      params: task
    };
    return queueNotification(notification, {
      type: 'MCP_TASK_STATUS_QUEUED',
      task_id: snapshot.task_id,
      status: task.status,
      hcp_status: snapshot.status,
      details
    });
  }

  function emitResourceUpdated(uri, details = {}) {
    if (typeof uri !== 'string' || uri.length === 0) {
      throw new InvalidInputError('MCP resource updated notification requires a non-empty uri', { uri });
    }
    if (!resourceSubscriptions.has(uri)) {
      throw new InvalidInputError('MCP resource updated notification requires an active subscription', {
        uri
      });
    }
    const notification = {
      jsonrpc: JSONRPC_VERSION,
      method: 'notifications/resources/updated',
      params: { uri }
    };
    return queueNotification(notification, {
      type: 'MCP_RESOURCE_UPDATED_QUEUED',
      uri,
      details
    });
  }

  function shouldEmitLogLevel(level) {
    return MCP_LOG_LEVEL_ORDER.indexOf(level) >= MCP_LOG_LEVEL_ORDER.indexOf(logLevel);
  }

  function emitLogMessage(level, data, { logger = null } = {}) {
    if (typeof level !== 'string' || !MCP_LOG_LEVELS.has(level)) {
      throw new InvalidInputError('MCP log message level must be a valid level', {
        level,
        allowed: [...MCP_LOG_LEVELS]
      });
    }
    const params = {
      level,
      data
    };
    if (logger !== null) {
      if (typeof logger !== 'string' || logger.length === 0) {
        throw new InvalidInputError('MCP log message logger must be a non-empty string when provided', { logger });
      }
      params.logger = logger;
    }

    if (!shouldEmitLogLevel(level)) {
      runtime.auditEntries.push({
        type: 'MCP_LOG_MESSAGE_SUPPRESSED',
        timestamp: new Date().toISOString(),
        principal,
        protocol: 'mcp',
        shim: info.name,
        level,
        logger,
        threshold: logLevel
      });
      return null;
    }

    const notification = {
      jsonrpc: JSONRPC_VERSION,
      method: 'notifications/message',
      params
    };
    return queueNotification(notification, {
      type: 'MCP_LOG_MESSAGE_QUEUED',
      level,
      logger,
      threshold: logLevel
    });
  }

  async function dispatch(method, params = {}) {
    if (stateless) {
      validateStatelessRequestMeta(params, { protocolVersion });
      if (MCP_STATELESS_REMOVED_METHODS.has(method) || method.startsWith('tasks/')) {
        throw new HcpError(`MCP method is not available in the 2026-07-28 stateless protocol: ${method}`, 'METHOD_NOT_FOUND', {
          method,
          protocolVersion
        });
      }
    } else if (!mcpInitialized && method !== 'initialize' && method !== 'notifications/initialized') {
      throw new HcpError('Call initialize before normal MCP-like shim methods', 'INITIALIZATION_REQUIRED', {
        method
      });
    }

    switch (method) {
      case 'server/discover':
        if (!stateless) {
          throw new HcpError('server/discover is only implemented by the MCP 2026-07-28 stateless protocol path', 'METHOD_NOT_FOUND', {
            method,
            protocolVersion
          });
        }
        return {
          supportedVersions,
          capabilities: mcpServerCapabilities({ stateless: true }),
          instructions: 'HCP reference runtime scoped MCP 2026-07-28 compatibility path. Protocol metadata is per request; HCP principal, grant, handle, and data-flow authority remain runtime-managed.'
        };
      case 'ping':
        return {};
      case 'initialize': {
        const clientVersion = params.protocolVersion ?? protocolVersion;
        if (clientVersion !== protocolVersion) {
          throw new HcpError('Protocol version mismatch', 'PROTOCOL_VERSION_MISMATCH', {
            expected: protocolVersion,
            received: clientVersion
          });
        }
        mcpInitialized = true;
        return {
          protocolVersion,
          capabilities: mcpServerCapabilities(),
          serverInfo: info,
          instructions: 'HCP runtime exposed through a minimal MCP-compatible tools/resources/prompts shim.'
        };
      }
      case 'notifications/initialized':
        mcpInitializedNotificationReceived = true;
        return { acknowledged: true };
      case 'notifications/cancelled': {
        runtime.auditEntries.push({
          type: 'MCP_REQUEST_CANCELLED',
          timestamp: new Date().toISOString(),
          principal,
          protocol: 'mcp',
          shim: info.name,
          request_id: params.requestId ?? null,
          reason: params.reason ?? null
        });
        return { acknowledged: true };
      }
      case 'notifications/progress': {
        runtime.auditEntries.push({
          type: 'MCP_PROGRESS_REPORTED',
          timestamp: new Date().toISOString(),
          principal,
          protocol: 'mcp',
          shim: info.name,
          progress_token: params.progressToken ?? null,
          progress: params.progress ?? null,
          total: params.total ?? null,
          message: params.message ?? null
        });
        return { acknowledged: true };
      }
      case 'notifications/roots/list_changed': {
        runtime.auditEntries.push({
          type: 'MCP_ROOTS_LIST_CHANGED',
          timestamp: new Date().toISOString(),
          principal,
          protocol: 'mcp',
          shim: info.name,
          reason: params.reason ?? null
        });
        return { acknowledged: true };
      }
      case 'notifications/tools/list_changed':
        emitListChanged('tools', {
          reason: params.reason ?? null
        });
        return { acknowledged: true };
      case 'notifications/resources/list_changed':
        emitListChanged('resources', {
          reason: params.reason ?? null
        });
        return { acknowledged: true };
      case 'notifications/prompts/list_changed':
        emitListChanged('prompts', {
          reason: params.reason ?? null
        });
        return { acknowledged: true };
      case 'notifications/resources/updated': {
        emitResourceUpdated(params.uri, {
          reason: params.reason ?? null
        });
        return { acknowledged: true };
      }
      case 'tools/list':
        return mcpListPage('tools', await facade.listTools(params), params);
      case 'tools/call': {
        const result = await facade.callTool({
          name: params.name,
          arguments: params.arguments ?? {},
          task: params.task,
          inputResponses: params.inputResponses,
          requestState: params.requestState,
          _meta: params._meta
        });
        if (params.task && result?.task?.taskId) {
          emitTaskStatus(result.hcp_task ?? runtime.taskSnapshot(result.task.taskId), {
            method: 'tools/call'
          });
        }
        return result;
      }
      case 'tasks/list':
        return mcpListPage('tasks', await facade.listTasks(params.filter ?? {}), params);
      case 'tasks/get':
        return facade.getTask(params);
      case 'tasks/result':
        return facade.taskResult(params);
      case 'tasks/cancel': {
        const result = await facade.cancelTask(params);
        emitTaskStatus(runtime.taskSnapshot(result.taskId), {
          method: 'tasks/cancel'
        });
        return result;
      }
      case 'resources/list':
        return mcpListPage('resources', await facade.listResources(params), params);
      case 'resources/templates/list':
        return mcpListPage('resourceTemplates', await facade.listResourceTemplates(params), params);
      case 'resources/subscribe': {
        const uri = params.uri;
        if (typeof uri !== 'string' || uri.length === 0) {
          throw new InvalidInputError('MCP resource subscription requires a non-empty uri', { uri });
        }
        const resources = await facade.listResources();
        if (!resources.some((resource) => resource.uri === uri)) {
          throw new HcpError(`Unknown MCP resource URI for subscription: ${uri}`, 'NOT_FOUND', { uri });
        }
        resourceSubscriptions.add(uri);
        runtime.auditEntries.push({
          type: 'MCP_RESOURCE_SUBSCRIBED',
          timestamp: new Date().toISOString(),
          principal,
          protocol: 'mcp',
          shim: info.name,
          uri
        });
        return {};
      }
      case 'resources/unsubscribe': {
        const uri = params.uri;
        if (typeof uri !== 'string' || uri.length === 0) {
          throw new InvalidInputError('MCP resource unsubscribe requires a non-empty uri', { uri });
        }
        resourceSubscriptions.delete(uri);
        runtime.auditEntries.push({
          type: 'MCP_RESOURCE_UNSUBSCRIBED',
          timestamp: new Date().toISOString(),
          principal,
          protocol: 'mcp',
          shim: info.name,
          uri
        });
        return {};
      }
      case 'resources/read':
        return facade.readResource({ uri: params.uri });
      case 'prompts/list':
        return mcpListPage('prompts', await facade.listPrompts(params), params);
      case 'prompts/get':
        return facade.getPrompt({
          name: params.name,
          arguments: params.arguments ?? {}
        });
      case 'completion/complete':
        return facade.complete({
          ref: params.ref ?? {},
          argument: params.argument ?? {},
          context: params.context ?? {}
        });
      case 'roots/list': {
        const roots = runtime.rootList({}, { principal });
        return { roots: roots.map(toMcpRoot) };
      }
      case 'sampling/createMessage': {
        const modelRequest = runtime.modelRequest(params, {
          principal,
          origin: `mcp:${info.name}`,
          reason: 'mcp.sampling/createMessage'
        });
        return {
          status: modelRequest.status,
          hcp_model_request: modelRequest
        };
      }
      case 'elicitation/create': {
        const inputRequest = runtime.inputRequest(
          params.schema ?? {},
          params.prompt ?? params.message ?? 'Provide requested input',
          {
            principal,
            reason: 'mcp.elicitation/create'
          }
        );
        return {
          status: inputRequest.status,
          hcp_input_request: inputRequest
        };
      }
      case 'logging/setLevel': {
        const level = params.level;
        if (typeof level !== 'string' || !MCP_LOG_LEVELS.has(level)) {
          throw new InvalidInputError('MCP logging level must be a valid level', {
            level,
            allowed: [...MCP_LOG_LEVELS]
          });
        }
        logLevel = level;
        runtime.auditEntries.push({
          type: 'MCP_LOG_LEVEL_SET',
          timestamp: new Date().toISOString(),
          principal,
          level,
          protocol: 'mcp',
          shim: info.name
        });
        emitLogMessage(level, {
          message: `MCP logging level set to ${level}`
        }, {
          logger: info.name
        });
        return {};
      }
      default:
        throw new HcpError(`Unknown MCP shim method: ${method}`, 'METHOD_NOT_FOUND', { method });
    }
  }

  function handleMessage(message) {
    return withAuditAttempt(runtime, {
      principal,
      method: message?.method ?? 'unknown',
      request_id: message?.id ?? null,
      object: message?.params?.name ?? message?.params?.uri ?? 'unavailable'
    }, () => handleMessageInAttempt(message));
  }

  async function handleMessageInAttempt(message) {
    if (!isObject(message) || message.jsonrpc !== JSONRPC_VERSION || typeof message.method !== 'string') {
      auditRequestDenial('INVALID_REQUEST');
      return mcpJsonRpcError(
        hasId(message ?? {}) ? message.id : null,
        MCP_JSONRPC_ERRORS.INVALID_REQUEST,
        'INVALID_REQUEST'
      );
    }

    const id = hasId(message) ? message.id : null;
    const isNotification = !hasId(message);

    try {
      const result = await dispatch(message.method, isObject(message.params) ? message.params : {});
      const cacheable = new Set([
        'tools/list',
        'resources/list',
        'resources/templates/list',
        'resources/read',
        'prompts/list'
      ]);
      const modernResult = stateless
        ? withStatelessResponseMeta(
          cacheable.has(message.method) ? withConservativeCacheHints(result) : result,
          info
        )
        : result;
      return isNotification ? null : mcpJsonRpcResult(id, modernResult);
    } catch (error) {
      auditRequestDenial(error.code ?? 'INTERNAL_ERROR');
      if (isNotification) return stateless ? toMcpJsonRpcError(null, error) : null;
      return toMcpJsonRpcError(id, error);
    }
  }

  return {
    protocolVersion,
    stateless,
    supportedProtocolVersions: [...supportedVersions],
    serverInfo: info,
    get logLevel() {
      return logLevel;
    },
    get initialized() {
      return mcpInitialized;
    },
    get initializedNotificationReceived() {
      return mcpInitializedNotificationReceived;
    },
    get resourceSubscriptions() {
      return new Set(resourceSubscriptions);
    },
    get notificationQueue() {
      return notificationQueue.map((notification) => ({ ...notification }));
    },

    emitListChanged,
    emitTaskStatus,
    emitResourceUpdated,
    emitLogMessage,

    drainNotifications() {
      return notificationQueue.splice(0).map((notification) => ({ ...notification }));
    },

    async handleJson(raw) {
      let message;
      try {
        message = typeof raw === 'string' ? JSON.parse(raw) : raw;
      } catch (error) {
        return mcpJsonRpcError(null, MCP_JSONRPC_ERRORS.PARSE_ERROR, 'PARSE_ERROR', {
          message: error.message
        });
      }

      if (Array.isArray(message)) {
        if (message.length === 0) {
          return mcpJsonRpcError(null, MCP_JSONRPC_ERRORS.INVALID_REQUEST, 'INVALID_REQUEST');
        }
        const responses = [];
        for (const item of message) {
          const response = await handleMessage(item);
          if (response !== null) responses.push(response);
        }
        return responses.length > 0 ? responses : null;
      }

      return handleMessage(message);
    }
  };
}
