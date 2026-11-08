import { HcpError, InvalidInputError } from '../errors.js';

export const JSONRPC_VERSION = '2.0';

// Keep the original shim as a separately selectable legacy protocol era. The
// 2026-07-28 path deliberately does not reuse its initialize/session state.
export const MCP_LEGACY_PROTOCOL_VERSION = '2025-11-25';
export const MCP_STATELESS_PROTOCOL_VERSION = '2026-07-28';
export const MCP_SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([
  MCP_LEGACY_PROTOCOL_VERSION,
  MCP_STATELESS_PROTOCOL_VERSION
]);

export const MCP_PROTOCOL_VERSION = MCP_LEGACY_PROTOCOL_VERSION;
export const MCP_PROTOCOL_META_KEY = 'io.modelcontextprotocol/protocolVersion';
export const MCP_CLIENT_INFO_META_KEY = 'io.modelcontextprotocol/clientInfo';
export const MCP_CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities';
export const MCP_LOG_LEVEL_META_KEY = 'io.modelcontextprotocol/logLevel';
export const MCP_SERVER_INFO_META_KEY = 'io.modelcontextprotocol/serverInfo';

export const MCP_JSONRPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  RESOURCE_NOT_FOUND: -32002,
  INTERNAL_ERROR: -32603,
  HCP_ERROR: -32010
};

export const MCP_LOG_LEVEL_ORDER = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];
export const MCP_LOG_LEVELS = new Set(MCP_LOG_LEVEL_ORDER);
export const MCP_LIST_PAGE_SIZE = 100;
export const MCP_NOTIFICATION_QUEUE_LIMIT = 100;
export const MCP_LIST_CHANGED_METHODS = {
  tools: 'notifications/tools/list_changed',
  resources: 'notifications/resources/list_changed',
  prompts: 'notifications/prompts/list_changed'
};

export const MCP_STATELESS_REMOVED_METHODS = new Set([
  'initialize',
  'notifications/initialized',
  'logging/setLevel',
  'resources/subscribe',
  'resources/unsubscribe'
]);

export function isStatelessMcpProtocolVersion(protocolVersion) {
  return protocolVersion === MCP_STATELESS_PROTOCOL_VERSION;
}

export function sanitizeId(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '.')
    .replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, '') || 'tool';
}

export function toolCapabilityId(providerId, toolName) {
  return `${providerId}.${sanitizeId(toolName)}`;
}

export function resourceCapabilityId(providerId, resource) {
  return `${providerId}.resource.${sanitizeId(resource.name ?? resource.uri)}`;
}

export function promptCapabilityId(providerId, promptName) {
  return `${providerId}.prompt.${sanitizeId(promptName)}`;
}

export function defaultToolResource(toolName) {
  return `mcp:${sanitizeId(toolName)}`;
}

export function defaultMcpResource(resource) {
  return `mcp-resource:${sanitizeId(resource.uri ?? resource.name)}`;
}

export function toMcpRoot(root) {
  return {
    uri: root.uri,
    name: root.name ?? root.uri,
    hcp_root: {
      id: root.id,
      resource: root.resource ?? null,
      scopes: root.scopes ?? []
    }
  };
}

export function toMcpTaskStatus(status) {
  switch (status) {
    case 'COMPLETED':
      return 'completed';
    case 'FAILED':
      return 'failed';
    case 'CANCELLED':
      return 'cancelled';
    case 'WAITING_APPROVAL':
    case 'WAITING_INPUT':
    case 'PAUSED':
      return 'input_required';
    default:
      return 'working';
  }
}

export function mcpTaskStatusMessage(task) {
  if (task.error?.message) return task.error.message;
  switch (toMcpTaskStatus(task.status)) {
    case 'completed':
      return 'The operation completed successfully.';
    case 'failed':
      return 'The operation failed.';
    case 'cancelled':
      return 'The task was cancelled by request.';
    case 'input_required':
      return 'The operation requires additional input or approval.';
    default:
      return 'The operation is now in progress.';
  }
}

export function toMcpTask(task) {
  return {
    taskId: task.task_id,
    status: toMcpTaskStatus(task.status),
    statusMessage: mcpTaskStatusMessage(task),
    createdAt: task.created_at,
    lastUpdatedAt: task.updated_at,
    ttl: task.ttl_ms ?? null,
    pollInterval: 5000,
    _meta: {
      hcp_task_id: task.task_id,
      hcp_status: task.status,
      hcp_capability: task.capability_id,
      hcp_resource: task.resource ?? null
    }
  };
}

export function mcpTaskId(params = {}) {
  const taskId = params.taskId ?? params.task_id ?? params.id;
  if (typeof taskId !== 'string' || taskId.length === 0) {
    throw new InvalidInputError('MCP task method requires a non-empty taskId', { params });
  }
  return taskId;
}

export function relatedTaskMeta(task) {
  return {
    'io.modelcontextprotocol/related-task': {
      taskId: task.task_id
    }
  };
}

export function defaultPromptResource(promptName) {
  return `mcp-prompt:${sanitizeId(promptName)}`;
}

export function promptArgumentProperties(prompt) {
  const properties = {};
  for (const argument of prompt.arguments ?? []) {
    if (argument?.name) {
      properties[argument.name] = {
        type: argument.type ?? 'string',
        description: argument.description ?? ''
      };
    }
  }
  return properties;
}

export function promptArgumentsArray(prompt) {
  if (!Array.isArray(prompt.arguments)) return [];
  return prompt.arguments
    .filter((argument) => argument?.name)
    .map((argument) => ({ ...argument }));
}

export function mcpDisplayFields(item, fields = ['title', 'mimeType', 'icons', 'annotations', 'size']) {
  const metadata = {};
  for (const field of fields) {
    if (item?.[field] !== undefined) {
      metadata[field] = item[field];
    }
  }
  return metadata;
}

export function isMcpToolResult(value) {
  return isObject(value) && (
    Array.isArray(value.content) ||
    Object.prototype.hasOwnProperty.call(value, 'structuredContent') ||
    Object.prototype.hasOwnProperty.call(value, 'isError')
  );
}

export function normalizeTool(tool) {
  if (!tool || typeof tool.name !== 'string' || tool.name.length === 0) {
    throw new InvalidInputError('MCP tool must include a non-empty name', { tool });
  }
  return tool;
}

export function normalizeResource(resource) {
  if (!resource || typeof resource.uri !== 'string' || resource.uri.length === 0) {
    throw new InvalidInputError('MCP resource must include a non-empty uri', { resource });
  }
  return resource;
}

export function normalizeResourceTemplate(template) {
  if (!template || typeof template.uriTemplate !== 'string' || template.uriTemplate.length === 0) {
    throw new InvalidInputError('MCP resource template must include a non-empty uriTemplate', { template });
  }
  return template;
}

export function normalizePrompt(prompt) {
  if (!prompt || typeof prompt.name !== 'string' || prompt.name.length === 0) {
    throw new InvalidInputError('MCP prompt must include a non-empty name', { prompt });
  }
  return prompt;
}

export function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

export function validateStatelessRequestMeta(params, { protocolVersion }) {
  const meta = params?._meta;
  if (!isObject(meta)) {
    throw new InvalidInputError('MCP 2026-07-28 requests require an object params._meta envelope', {
      required: [MCP_PROTOCOL_META_KEY, MCP_CLIENT_CAPABILITIES_META_KEY]
    });
  }

  const receivedProtocolVersion = meta[MCP_PROTOCOL_META_KEY];
  if (receivedProtocolVersion !== protocolVersion) {
    throw new InvalidInputError('MCP request metadata has an unexpected protocol version', {
      expected: protocolVersion,
      received: receivedProtocolVersion ?? null,
      field: MCP_PROTOCOL_META_KEY
    });
  }

  // The final 2026-07-28 revision permits anonymous clientInfo, but when it is
  // supplied it must still be well formed. Client identity remains descriptive
  // metadata and is never promoted to an HCP principal.
  if (meta[MCP_CLIENT_INFO_META_KEY] !== undefined) {
    const clientInfo = meta[MCP_CLIENT_INFO_META_KEY];
    if (!isObject(clientInfo) || !isNonEmptyString(clientInfo.name) || !isNonEmptyString(clientInfo.version)) {
      throw new InvalidInputError('MCP clientInfo metadata must contain non-empty name and version fields', {
        field: MCP_CLIENT_INFO_META_KEY
      });
    }
  }

  // The 2026-07-28 revision marks clientCapabilities as required on every
  // request. A request missing it is malformed and is rejected with -32602
  // (HTTP 400), the same as a missing protocol version.
  if (!isObject(meta[MCP_CLIENT_CAPABILITIES_META_KEY])) {
    throw new InvalidInputError('MCP 2026-07-28 requests require an object clientCapabilities metadata field', {
      field: MCP_CLIENT_CAPABILITIES_META_KEY,
      received: meta[MCP_CLIENT_CAPABILITIES_META_KEY] ?? null
    });
  }

  if (meta[MCP_LOG_LEVEL_META_KEY] !== undefined && !MCP_LOG_LEVELS.has(meta[MCP_LOG_LEVEL_META_KEY])) {
    throw new InvalidInputError('MCP logLevel metadata must be a valid log level when provided', {
      field: MCP_LOG_LEVEL_META_KEY,
      allowed: [...MCP_LOG_LEVELS]
    });
  }

  return meta;
}

export function withStatelessRequestMeta(params, {
  protocolVersion,
  clientInfo,
  clientCapabilities,
  logLevel
}) {
  const base = isObject(params) ? params : {};
  const suppliedMeta = isObject(base._meta) ? base._meta : {};
  const meta = {
    ...suppliedMeta,
    [MCP_PROTOCOL_META_KEY]: protocolVersion,
    [MCP_CLIENT_CAPABILITIES_META_KEY]: clientCapabilities ?? {}
  };
  if (clientInfo) meta[MCP_CLIENT_INFO_META_KEY] = clientInfo;
  if (logLevel !== undefined && logLevel !== null) meta[MCP_LOG_LEVEL_META_KEY] = logLevel;
  return {
    ...base,
    _meta: meta
  };
}

export function withStatelessResponseMeta(result, serverInfo) {
  if (!isObject(result)) return result;
  const meta = isObject(result._meta) ? result._meta : {};
  return {
    ...result,
    _meta: {
      ...meta,
      [MCP_SERVER_INFO_META_KEY]: serverInfo
    }
  };
}

export function withConservativeCacheHints(result) {
  if (!isObject(result)) return result;
  return {
    ...result,
    ttlMs: result.ttlMs ?? 0,
    cacheScope: result.cacheScope ?? 'private'
  };
}

export function mcpServerCapabilities({ stateless = false } = {}) {
  const capabilities = {
    tools: {
      listChanged: true
    },
    resources: {
      ...(stateless ? {} : { subscribe: true }),
      listChanged: true
    },
    prompts: {
      listChanged: true
    },
    completions: {
      complete: true
    }
  };

  if (!stateless) {
    Object.assign(capabilities, {
      roots: {
        listChanged: true
      },
      sampling: {
        createMessage: true
      },
      elicitation: {
        create: true
      },
      logging: {
        setLevel: true
      },
      tasks: {
        list: {},
        cancel: {},
        requests: {
          tools: {
            call: {}
          }
        }
      }
    });
  }

  return capabilities;
}

export function hasId(message) {
  return Object.prototype.hasOwnProperty.call(message, 'id');
}

export function mcpJsonRpcResult(id, result) {
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    result
  };
}

export function mcpJsonRpcError(id, code, message, data = undefined) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    error
  };
}

export function toMcpJsonRpcError(id, error) {
  if (error instanceof HcpError) {
    if (error.code === 'MISSING_REQUIRED_CLIENT_CAPABILITY') {
      return mcpJsonRpcError(id, -32021, error.code, error.details);
    }
    const codeByHcpCode = {
      METHOD_NOT_FOUND: MCP_JSONRPC_ERRORS.METHOD_NOT_FOUND,
      INVALID_INPUT: MCP_JSONRPC_ERRORS.INVALID_PARAMS,
      NOT_FOUND: MCP_JSONRPC_ERRORS.RESOURCE_NOT_FOUND
    };
    const code = codeByHcpCode[error.code] ?? MCP_JSONRPC_ERRORS.HCP_ERROR;
    return mcpJsonRpcError(id, code, error.code, {
      hcp_code: error.code,
      message: error.message,
      details: error.details ?? {}
    });
  }

  return mcpJsonRpcError(id, MCP_JSONRPC_ERRORS.INTERNAL_ERROR, 'INTERNAL_ERROR', {
    message: error?.message ?? String(error)
  });
}

export function toMcpClientError(response) {
  const error = response?.error ?? {};
  return new HcpError(error.message ?? 'MCP_JSONRPC_ERROR', 'MCP_JSONRPC_ERROR', {
    jsonrpc_code: error.code ?? null,
    data: error.data ?? null
  });
}

export function isMethodNotFound(error) {
  return error instanceof HcpError &&
    error.code === 'MCP_JSONRPC_ERROR' &&
    error.details?.jsonrpc_code === MCP_JSONRPC_ERRORS.METHOD_NOT_FOUND;
}

export function decodeListCursor(cursor) {
  if (cursor === undefined || cursor === null || cursor === '') return 0;
  const value = Number.parseInt(String(cursor), 10);
  if (!Number.isInteger(value) || String(value) !== String(cursor) || value < 0) {
    throw new InvalidInputError('MCP list cursor must be a non-negative integer string', { cursor });
  }
  return value;
}

export function mcpListPage(field, items, params = {}) {
  const start = decodeListCursor(params.cursor);
  const values = items.slice(start, start + MCP_LIST_PAGE_SIZE);
  const next = start + values.length;
  const result = { [field]: values };
  if (next < items.length) result.nextCursor = String(next);
  return result;
}
