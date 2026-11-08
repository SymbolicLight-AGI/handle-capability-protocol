import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { applyTransform, detectSensitiveSecrets, redactSensitiveSecrets } from '../core/projection.js';
import { HcpError, InvalidInputError } from '../errors.js';
import { serveJsonRpcHttp } from '../http-server.js';
import { makeProvider } from '../provider-sdk.js';
import { DefaultPolicyEngine, HcpRuntime } from '../runtime.js';
import { createRequestStateAuthority } from '../mrtr.js';
import { createMcpClientShimDispatcher } from './client-shim.js';
import { serveMcpStdio } from '../stdio-server.js';
import { HCP_RUNTIME_VERSION } from '../package-info.js';
import {
  MCP_PROTOCOL_VERSION,
  defaultMcpResource,
  defaultPromptResource,
  defaultToolResource,
  isObject,
  sanitizeId
} from './common.js';
import {
  wrapMcpHttpServerAsProvider,
  wrapMcpJsonRpcServerAsProvider,
  wrapMcpServerAsProvider,
  wrapMcpStdioServerAsProvider
} from './server-wrapper.js';

export const DEFAULT_MCP_PROXY_PRINCIPAL = 'user:local';

// How write-class upstream tools are authorized by the proxy.
//  - explicit: only read-only tools are auto-granted; a write tool runs only if
//    policy.json lists it in `grants`, and that listing is the approval.
//  - prompt:   every tool is granted, write tools pause for a human approval
//    delivered through MCP elicitation (MRTR input-required round trip). This
//    requires a client that declares form elicitation support.
//  - auto:     every tool is granted and pre-approved; HCP still audits,
//    intercepts secrets and offloads large outputs.
export const MCP_PROXY_APPROVAL_MODES = Object.freeze(['explicit', 'prompt', 'auto']);
export const DEFAULT_MCP_PROXY_APPROVAL_MODE = 'explicit';

function normalizeApprovalMode(mode, legacyApproval = null) {
  if (mode === undefined || mode === null || mode === '') {
    return isObject(legacyApproval) && legacyApproval.approved === true ? 'auto' : DEFAULT_MCP_PROXY_APPROVAL_MODE;
  }
  if (!MCP_PROXY_APPROVAL_MODES.includes(mode)) {
    throw new InvalidInputError(
      `MCP proxy approval_mode must be one of ${MCP_PROXY_APPROVAL_MODES.join(', ')}`,
      { approval_mode: mode }
    );
  }
  return mode;
}

function defaultAutoGrantFor(approvalMode) {
  return approvalMode === 'explicit' ? 'read_only' : true;
}

// MCP tool annotations are untrusted hints from the upstream server, so the
// classification is conservative: only an explicit readOnlyHint (without a
// destructiveHint) is treated as a read; anything unannotated is a write.
export function classifyMcpToolEffects(annotations) {
  const hints = isObject(annotations) ? annotations : {};
  if (hints.destructiveHint === true) return { kind: 'write', risk: 'high' };
  if (hints.readOnlyHint === true) return { kind: 'read', risk: 'low' };
  return { kind: 'write', risk: 'medium' };
}

export const DEFAULT_MCP_PROXY_OUTPUT_POLICY = Object.freeze({
  intercept_secrets: true,
  secret_release_policy: 'redacted_only',
  offload_large_outputs: true,
  large_release_policy: 'full',
  max_inline_bytes: 4096,
  preview_bytes: 512,
  expose_vault_tools: true,
  resolve_input_handles: true
});

function normalizeOutputPolicy(policy = {}, override = {}) {
  const merged = {
    ...DEFAULT_MCP_PROXY_OUTPUT_POLICY,
    ...(isObject(policy) ? policy : {}),
    ...(isObject(override) ? override : {})
  };
  const maxInlineBytes = Number.parseInt(String(merged.max_inline_bytes), 10);
  const previewBytes = Number.parseInt(String(merged.preview_bytes), 10);
  return {
    intercept_secrets: Boolean(merged.intercept_secrets),
    secret_release_policy: typeof merged.secret_release_policy === 'string'
      ? merged.secret_release_policy
      : DEFAULT_MCP_PROXY_OUTPUT_POLICY.secret_release_policy,
    offload_large_outputs: Boolean(merged.offload_large_outputs),
    large_release_policy: typeof merged.large_release_policy === 'string'
      ? merged.large_release_policy
      : DEFAULT_MCP_PROXY_OUTPUT_POLICY.large_release_policy,
    max_inline_bytes: Number.isInteger(maxInlineBytes) && maxInlineBytes > 0
      ? maxInlineBytes
      : DEFAULT_MCP_PROXY_OUTPUT_POLICY.max_inline_bytes,
    preview_bytes: Number.isInteger(previewBytes) && previewBytes > 0
      ? previewBytes
      : DEFAULT_MCP_PROXY_OUTPUT_POLICY.preview_bytes,
    expose_vault_tools: merged.expose_vault_tools !== false,
    resolve_input_handles: merged.resolve_input_handles !== false
  };
}

async function loadSecretsMap(secretsFilePath) {
  if (!secretsFilePath || typeof secretsFilePath !== 'string') return {};
  if (!existsSync(secretsFilePath)) return {};
  const raw = await readFile(secretsFilePath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new InvalidInputError(`HCP secrets file is not valid JSON: ${secretsFilePath}`, {
      secrets_path: secretsFilePath,
      cause: error.message
    });
  }
  const rawSecrets = isObject(parsed?.secrets) ? parsed.secrets : (isObject(parsed) ? parsed : {});
  const map = {};
  for (const [key, entry] of Object.entries(rawSecrets)) {
    const value = isObject(entry) && typeof entry.value === 'string'
      ? entry.value
      : (typeof entry === 'string' ? entry : null);
    if (value === null) continue;
    map[key] = value;
    if (isObject(entry) && typeof entry.ref === 'string' && entry.ref.startsWith('env:')) {
      const envName = entry.ref.slice('env:'.length);
      if (!(envName in map)) map[envName] = value;
    }
    const parts = key.split('.');
    if (parts.length >= 3 && parts[0] === 'mcp') {
      const envName = parts.slice(2).join('.');
      if (!(envName in map)) map[envName] = value;
    }
  }
  return map;
}

const UNRESOLVED = Symbol('hcp.unresolved_secret_ref');

function resolveEnvValue(rawValue, secretsMap = {}, env = process.env, serverId = null, envKey = null) {
  if (typeof rawValue !== 'string') return String(rawValue ?? '');
  const lookup = (candidate) => {
    if (serverId && Object.prototype.hasOwnProperty.call(secretsMap, `mcp.${serverId}.${candidate}`)) {
      return String(secretsMap[`mcp.${serverId}.${candidate}`]);
    }
    if (Object.prototype.hasOwnProperty.call(secretsMap, candidate)) {
      return String(secretsMap[candidate]);
    }
    if (Object.prototype.hasOwnProperty.call(env, candidate)) {
      return String(env[candidate]);
    }
    return null;
  };
  if (rawValue.startsWith('$HCP_ENV:')) {
    const refKey = rawValue.slice('$HCP_ENV:'.length).trim();
    return lookup(refKey) ?? (envKey ? lookup(envKey) : null) ?? UNRESOLVED;
  }
  const envRefMatch = /^\$\{env:([A-Za-z0-9_.-]+)\}$/.exec(rawValue);
  if (envRefMatch) {
    return lookup(envRefMatch[1]) ?? (envKey ? lookup(envKey) : null) ?? UNRESOLVED;
  }
  const braceMatch = /^\$\{([A-Za-z0-9_.-]+)\}$/.exec(rawValue);
  if (braceMatch) {
    return lookup(braceMatch[1]) ?? (envKey ? lookup(envKey) : null) ?? UNRESOLVED;
  }
  return rawValue;
}

// Unresolved secret references are never forwarded as their literal
// placeholder text; the key is dropped and reported so the operator sees why
// an upstream server is missing credentials.
function resolveEnvMap(envConfig = {}, secretsMap = {}, env = process.env, serverId = null, unresolved = []) {
  if (!isObject(envConfig)) return {};
  const resolved = {};
  for (const [key, value] of Object.entries(envConfig)) {
    let next;
    if (isObject(value) && typeof value.value === 'string') {
      next = resolveEnvValue(value.value, secretsMap, env, serverId, key);
    } else if (typeof value === 'string') {
      next = resolveEnvValue(value, secretsMap, env, serverId, key);
    } else if (value !== undefined && value !== null) {
      next = String(value);
    } else {
      continue;
    }
    if (next === UNRESOLVED) {
      unresolved.push({ server: serverId, key });
      continue;
    }
    resolved[key] = next;
  }
  return resolved;
}

function normalizeServerEntry(id, rawServer = {}, index = 0) {
  if (!isObject(rawServer)) {
    throw new InvalidInputError('MCP proxy server entry must be an object', { id, rawServer });
  }
  const serverId = sanitizeId(rawServer.id ?? id ?? `server_${index + 1}`);
  const providerId = sanitizeId(rawServer.provider_id ?? rawServer.providerId ?? `mcp.${serverId}`);
  const transportType = rawServer.transport_type ?? rawServer.transport ?? (
    rawServer.origin || rawServer.url ? 'http' : 'stdio'
  );
  const origin = rawServer.origin ?? rawServer.url ?? null;
  return {
    id: serverId,
    provider_id: providerId,
    title: rawServer.title ?? `Proxied MCP Server (${serverId})`,
    version: rawServer.version ?? '0.1.0',
    enabled: rawServer.enabled !== false,
    transport: transportType,
    command: rawServer.command ?? null,
    args: Array.isArray(rawServer.args) ? rawServer.args.map(String) : [],
    cwd: rawServer.cwd ?? null,
    env: isObject(rawServer.env) ? { ...rawServer.env } : {},
    origin,
    path: rawServer.path ?? '/mcp',
    headers: isObject(rawServer.headers) ? { ...rawServer.headers } : {},
    timeout_ms: Number.isInteger(rawServer.timeout_ms ?? rawServer.timeoutMs)
      ? (rawServer.timeout_ms ?? rawServer.timeoutMs)
      : 10000,
    protocol_version: rawServer.protocol_version ?? rawServer.protocolVersion ?? MCP_PROTOCOL_VERSION,
    capability_overrides: isObject(rawServer.capability_overrides ?? rawServer.capabilityOverrides)
      ? { ...(rawServer.capability_overrides ?? rawServer.capabilityOverrides) }
      : {},
    output_policy: isObject(rawServer.output_policy ?? rawServer.outputPolicy)
      ? { ...(rawServer.output_policy ?? rawServer.outputPolicy) }
      : null,
    auto_grant: rawServer.auto_grant ?? rawServer.autoGrant ?? undefined,
    mcpServer: rawServer.mcpServer ?? null,
    transportInstance: isObject(rawServer.transport) && typeof rawServer.transport.request === 'function'
      ? rawServer.transport
      : null
  };
}

function normalizeServersCollection(rawServers) {
  if (Array.isArray(rawServers)) {
    return rawServers.map((entry, index) => normalizeServerEntry(entry?.id, entry, index));
  }
  if (isObject(rawServers)) {
    return Object.entries(rawServers).map(([id, entry], index) => normalizeServerEntry(id, entry, index));
  }
  return [];
}

export function createDefaultMcpProxyPolicy({
  servers = {},
  principal = DEFAULT_MCP_PROXY_PRINCIPAL,
  auditLogPath = '.hcp/audit.jsonl',
  secretsFile = '.hcp/secrets.json',
  outputPolicy = {},
  grants = [],
  autoGrant = undefined,
  approvalMode = DEFAULT_MCP_PROXY_APPROVAL_MODE,
  approval = null
} = {}) {
  const normalizedServers = normalizeServersCollection(servers);
  const serversMap = {};
  for (const server of normalizedServers) {
    serversMap[server.id] = {
      provider_id: server.provider_id,
      title: server.title,
      transport: typeof server.transport === 'string' ? server.transport : 'stdio',
      ...(server.command ? { command: server.command, args: server.args } : {}),
      ...(server.cwd ? { cwd: server.cwd } : {}),
      ...(Object.keys(server.env).length > 0 ? { env: server.env } : {}),
      ...(server.origin ? { origin: server.origin, path: server.path } : {}),
      ...(Object.keys(server.headers).length > 0 ? { headers: server.headers } : {}),
      ...(Object.keys(server.capability_overrides).length > 0 ? { capability_overrides: server.capability_overrides } : {}),
      ...(server.output_policy ? { output_policy: server.output_policy } : {})
    };
  }

  return {
    schema_version: '0.4-draft',
    kind: 'hcp-mcp-proxy-policy',
    principal,
    audit_log: auditLogPath,
    secrets_file: secretsFile,
    approval_mode: normalizeApprovalMode(approvalMode),
    ...(autoGrant !== undefined ? { auto_grant: autoGrant } : {}),
    ...(approval ? { approval } : {}),
    output_policy: normalizeOutputPolicy(outputPolicy),
    servers: serversMap,
    grants: Array.isArray(grants) ? grants : []
  };
}

export async function loadMcpProxyPolicy(policyOrPath = {}, {
  workspace = process.cwd(),
  secretsPath = null,
  env = process.env
} = {}) {
  let rawPolicy = policyOrPath;
  let policyPath = null;
  let baseDir = workspace;

  if (typeof policyOrPath === 'string' && policyOrPath.length > 0) {
    policyPath = path.isAbsolute(policyOrPath)
      ? policyOrPath
      : path.resolve(workspace, policyOrPath);
    baseDir = path.dirname(policyPath);
    const content = await readFile(policyPath, 'utf8');
    rawPolicy = JSON.parse(content);
  } else if (!isObject(rawPolicy)) {
    throw new InvalidInputError('MCP proxy policy must be a file path or policy object', {
      policy: policyOrPath
    });
  }

  const rawServers = rawPolicy.servers ?? rawPolicy.mcpServers ?? rawPolicy.mcp_servers ?? {};
  const servers = normalizeServersCollection(rawServers);

  const configuredSecretsFile = secretsPath
    ?? rawPolicy.secrets_file
    ?? rawPolicy.secretsFile
    ?? path.join(workspace, '.hcp', 'secrets.json');
  const resolvedSecretsPath = typeof configuredSecretsFile === 'string'
    ? (path.isAbsolute(configuredSecretsFile) ? configuredSecretsFile : path.resolve(workspace, configuredSecretsFile))
    : null;
  const secretsMap = await loadSecretsMap(resolvedSecretsPath);

  const unresolvedSecrets = [];
  for (const server of servers) {
    server.env = resolveEnvMap(server.env, secretsMap, env, server.id, unresolvedSecrets);
    server.headers = resolveEnvMap(server.headers, secretsMap, env, server.id, unresolvedSecrets);
    if (server.cwd && !path.isAbsolute(server.cwd)) {
      server.cwd = path.resolve(workspace, server.cwd);
    }
  }

  const configuredAuditLog = rawPolicy.audit_log ?? rawPolicy.auditLogPath ?? '.hcp/audit.jsonl';
  const resolvedAuditLogPath = configuredAuditLog === false || configuredAuditLog === null
    ? null
    : (path.isAbsolute(configuredAuditLog) ? configuredAuditLog : path.resolve(workspace, configuredAuditLog));

  const approvalMode = normalizeApprovalMode(rawPolicy.approval_mode ?? rawPolicy.approvalMode, rawPolicy.approval);
  const rawAutoGrant = rawPolicy.auto_grant ?? rawPolicy.autoGrant;

  return {
    schema_version: rawPolicy.schema_version ?? '0.4-draft',
    kind: rawPolicy.kind ?? 'hcp-mcp-proxy-policy',
    policy_path: policyPath,
    base_dir: baseDir,
    principal: rawPolicy.principal ?? DEFAULT_MCP_PROXY_PRINCIPAL,
    approval_mode: approvalMode,
    approval: rawPolicy.approval ?? null,
    auto_grant: rawAutoGrant !== undefined ? rawAutoGrant : defaultAutoGrantFor(approvalMode),
    unresolved_secrets: unresolvedSecrets,
    scope_discovery: Boolean(rawPolicy.scope_discovery ?? rawPolicy.scopeDiscovery ?? false),
    include_default_providers: Boolean(rawPolicy.include_default_providers ?? false),
    audit_log_path: resolvedAuditLogPath,
    secrets_path: resolvedSecretsPath,
    retention: isObject(rawPolicy.retention) ? { ...rawPolicy.retention } : {},
    output_policy: normalizeOutputPolicy(rawPolicy.output_policy ?? rawPolicy.outputPolicy),
    servers,
    grants: Array.isArray(rawPolicy.grants) ? rawPolicy.grants.map((grant) => ({ ...grant })) : []
  };
}

function serializeToolOutput(value) {
  if (typeof value === 'string') return value;
  return JSON.stringify(value ?? null);
}

function extractTextForPreview(rawResult) {
  if (typeof rawResult === 'string') return rawResult;
  if (isObject(rawResult) && Array.isArray(rawResult.content)) {
    const texts = rawResult.content
      .filter((item) => isObject(item) && typeof item.text === 'string')
      .map((item) => item.text);
    if (texts.length > 0) return texts.join('\n');
  }
  return serializeToolOutput(rawResult);
}

export function guardMcpToolOutput(rawResult, {
  runtime,
  principal = DEFAULT_MCP_PROXY_PRINCIPAL,
  capability,
  resource = null,
  outputPolicy = DEFAULT_MCP_PROXY_OUTPUT_POLICY
} = {}) {
  const policy = normalizeOutputPolicy(outputPolicy);
  const serialized = serializeToolOutput(rawResult);
  const byteLength = Buffer.byteLength(serialized, 'utf8');

  const secretFindings = policy.intercept_secrets
    ? detectSensitiveSecrets(rawResult)
    : [];
  const hasSecrets = secretFindings.length > 0;
  const isLarge = policy.offload_large_outputs && byteLength > policy.max_inline_bytes;

  if (!hasSecrets && !isLarge) {
    return rawResult;
  }

  const dataClass = [
    'external_content',
    ...(hasSecrets ? ['secret'] : []),
    ...(isLarge ? ['large_output'] : [])
  ];
  const releasePolicy = hasSecrets
    ? policy.secret_release_policy
    : policy.large_release_policy;

  const handle = runtime.dataVault.put(rawResult, {
    principal,
    source_capability: capability?.id ?? 'mcp.proxy',
    resource,
    data_class: dataClass,
    release_policy: releasePolicy
  });
  const record = runtime.dataVault.get(handle);

  const redactedValue = hasSecrets ? redactSensitiveSecrets(rawResult) : rawResult;
  const previewSource = extractTextForPreview(redactedValue);
  const boundedPreview = applyTransform(previewSource, {
    max_bytes: policy.preview_bytes
  });

  const reason = hasSecrets && isLarge
    ? 'SENSITIVE_SECRET_AND_LARGE_OUTPUT_INTERCEPTED'
    : hasSecrets
      ? 'SENSITIVE_SECRET_INTERCEPTED'
      : 'LARGE_OUTPUT_OFFLOADED';

  runtime.auditEntries.push({
    type: hasSecrets ? 'MCP_PROXY_SECRET_INTERCEPTED' : 'MCP_PROXY_OUTPUT_OFFLOADED',
    timestamp: new Date().toISOString(),
    principal,
    capability: capability?.id ?? null,
    resource,
    handle: record.handle,
    reason,
    original_bytes: byteLength,
    max_inline_bytes: policy.max_inline_bytes,
    secret_count: secretFindings.length,
    secret_types: [...new Set(secretFindings)],
    release_policy: releasePolicy
  });

  const envelope = {
    hcp_offloaded: true,
    hcp_handle: record.handle,
    reason,
    capability: capability?.id ?? null,
    resource,
    original_bytes: byteLength,
    max_inline_bytes: policy.max_inline_bytes,
    release_policy: releasePolicy,
    ...(hasSecrets
      ? { secret_types: [...new Set(secretFindings)] }
      : {}),
    ...(releasePolicy === 'pipe_only' ? {} : { digest: record.digest }),
    preview: boundedPreview,
    instructions: 'Raw tool output was intercepted by HCP proxy and stored in the local DataVault. Call hcp.data.peek (modes: preview, summary, metadata, full) or hcp.data.describe with hcp_handle to inspect under HCP policy.'
  };

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(envelope, null, 2)
      }
    ],
    structuredContent: envelope,
    _meta: {
      hcp_handle: record.handle,
      hcp_offloaded: true,
      hcp_reason: reason
    }
  };
}

const VAULT_HANDLE_PATTERN = /h:\/\/vault\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+/g;

export function resolveMcpToolHandleInputs(input, {
  runtime,
  principal = DEFAULT_MCP_PROXY_PRINCIPAL,
  capability,
  resource = null
} = {}) {
  if (!runtime || input === null || input === undefined) return input;

  function resolveAuthorizedHandle(handle) {
    let sourceRecord;
    try {
      sourceRecord = runtime.dataVault.get(handle);
      const owner = sourceRecord.metadata?.principal ?? null;
      if (owner && owner !== principal) {
        throw new HcpError('Handle pipe denied for principal', 'HANDLE_ACCESS_DENIED', {
          handle,
          principal,
          operation: 'mcp.proxy.pipe'
        });
      }
    } catch (error) {
      runtime.auditEntries.push({
        type: 'DATA_PIPE_SOURCE_DENIED',
        timestamp: new Date().toISOString(),
        principal,
        source_handle: handle,
        target_capability: capability?.id ?? null,
        target_resource: resource,
        allowed: false,
        reason: error.code ?? 'HCP_ERROR',
        code: error.code ?? 'HCP_ERROR',
        message: error.message
      });
      throw error;
    }

    runtime.auditEntries.push({
      type: 'DATA_PIPE_SOURCE_CHECK',
      timestamp: new Date().toISOString(),
      principal,
      source_handle: handle,
      source_capability: sourceRecord.metadata?.source_capability ?? sourceRecord.metadata?.source ?? null,
      source_resource: sourceRecord.metadata?.resource ?? null,
      target_capability: capability?.id ?? null,
      target_resource: resource,
      allowed: true,
      reason: 'SOURCE_HANDLE_ALLOWED'
    });

    const sourceClasses = Array.isArray(sourceRecord.metadata?.data_class)
      ? sourceRecord.metadata.data_class
      : [];
    const targetDataIn = Array.isArray(capability?.security?.data_in)
      ? capability.security.data_in
      : [];

    const hasSecret = sourceClasses.includes('secret');
    const targetAcceptsSecret = targetDataIn.includes('secret');
    const hasPii = sourceClasses.includes('pii') || sourceClasses.includes('contains_pii');
    const targetAcceptsPii = targetDataIn.includes('pii') || targetDataIn.includes('contains_pii');

    if ((hasSecret && !targetAcceptsSecret) || (hasPii && !targetAcceptsPii)) {
      const deniedClass = hasSecret && !targetAcceptsSecret ? 'secret' : 'pii';
      const denyReason = `target capability does not accept ${deniedClass}-class data`;
      runtime.auditEntries.push({
        type: 'DATA_PIPE_POLICY_DECISION',
        timestamp: new Date().toISOString(),
        principal,
        source_handle: handle,
        source_data_class: sourceClasses,
        target_capability: capability?.id ?? null,
        target_resource: resource,
        allowed: false,
        reason: denyReason
      });
      throw new HcpError(`Data pipe denied: ${denyReason}`, 'POLICY_DENIED', {
        handle,
        source_data_class: sourceClasses,
        target_capability: capability?.id ?? null,
        target_data_in: targetDataIn
      });
    }

    runtime.auditEntries.push({
      type: 'DATA_PIPE_POLICY_DECISION',
      timestamp: new Date().toISOString(),
      principal,
      source_handle: handle,
      source_data_class: sourceClasses,
      target_capability: capability?.id ?? null,
      target_resource: resource,
      allowed: true,
      reason: 'HANDLE_PIPE_RESOLVED'
    });

    return extractTextForPreview(sourceRecord.value);
  }

  function walk(node) {
    if (typeof node === 'string') {
      VAULT_HANDLE_PATTERN.lastIndex = 0;
      if (!VAULT_HANDLE_PATTERN.test(node)) return node;
      VAULT_HANDLE_PATTERN.lastIndex = 0;
      return node.replace(VAULT_HANDLE_PATTERN, (match) => resolveAuthorizedHandle(match));
    }
    if (Array.isArray(node)) {
      return node.map((item) => walk(item));
    }
    if (isObject(node)) {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        out[k] = walk(v);
      }
      return out;
    }
    return node;
  }

  return walk(input);
}

function hasExplicitEffectsOverride(capability, capabilityOverrides = {}) {
  const toolName = capability.mcp?.tool_name;
  const override = (toolName && capabilityOverrides[toolName]) ?? capabilityOverrides[capability.id];
  return isObject(override) && isObject(override.effects) && typeof override.effects.kind === 'string';
}

function wrapProviderWithOutputGuard(provider, { runtime, principal, outputPolicy, capabilityOverrides = {} }) {
  const normalizedPolicy = normalizeOutputPolicy(outputPolicy);
  return {
    ...provider,
    async manifest() {
      const manifest = await provider.manifest();
      return {
        ...manifest,
        capabilities: (manifest.capabilities ?? []).map((capability) => {
          if (!capability.mcp?.tool_name || hasExplicitEffectsOverride(capability, capabilityOverrides)) {
            return capability;
          }
          return {
            ...capability,
            effects: {
              ...(capability.effects ?? {}),
              ...classifyMcpToolEffects(capability.mcp?.tool?.annotations)
            }
          };
        })
      };
    },
    async invoke(context) {
      const callerPrincipal = context.options?.principal ?? principal;
      const resource = context.options?.resource
        ?? (typeof provider.resourceFor === 'function' ? await provider.resourceFor(context) : null);
      const effectiveInput = normalizedPolicy.resolve_input_handles
        ? resolveMcpToolHandleInputs(context.input, {
            runtime,
            principal: callerPrincipal,
            capability: context.capability,
            resource
          })
        : context.input;
      const rawResult = await provider.invoke({
        ...context,
        input: effectiveInput
      });
      return guardMcpToolOutput(rawResult, {
        runtime,
        principal: callerPrincipal,
        capability: context.capability,
        resource,
        outputPolicy: normalizedPolicy
      });
    }
  };
}

export function createMcpProxyVaultProvider(runtime, {
  providerId = 'hcp.data',
  defaultPrincipal = DEFAULT_MCP_PROXY_PRINCIPAL
} = {}) {
  const capabilities = [
    {
      id: `${providerId}.peek`,
      version: '0.1.0',
      title: 'Peek HCP Vault Handle',
      description: 'Inspect an offloaded HCP vault handle (h://vault/...) using a bounded projection (preview, summary, metadata, or full).',
      intents: ['peek handle', 'inspect handle', 'read offloaded output'],
      input_schema: {
        type: 'object',
        required: ['handle'],
        properties: {
          handle: { type: 'string', description: 'The h://vault/... handle identifier.' },
          mode: {
            type: 'string',
            enum: ['preview', 'summary', 'metadata', 'full'],
            description: 'Projection mode (default: preview).'
          },
          max_bytes: {
            type: 'integer',
            description: 'Optional UTF-8 byte limit for the returned projection.'
          },
          redactions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional redactions to apply (e.g., ["secret", "email", "phone"]).'
          }
        }
      },
      output_schema: { type: 'object' },
      effects: {
        kind: 'read',
        risk: 'low'
      },
      security: {
        required_scopes: ['hcp:data:peek'],
        data_in: ['handle_ref'],
        data_out: ['projected_content']
      },
      mcp: {
        tool_name: 'peek',
        tool: {
          name: 'peek',
          description: 'Inspect an offloaded HCP vault handle (h://vault/...) using a bounded projection (preview, summary, metadata, or full).'
        }
      }
    },
    {
      id: `${providerId}.describe`,
      version: '0.1.0',
      title: 'Describe HCP Vault Handle',
      description: 'Return metadata and data classes for an HCP vault handle without releasing payload content.',
      intents: ['describe handle', 'handle metadata'],
      input_schema: {
        type: 'object',
        required: ['handle'],
        properties: {
          handle: { type: 'string', description: 'The h://vault/... handle identifier.' }
        }
      },
      output_schema: { type: 'object' },
      effects: {
        kind: 'read',
        risk: 'low'
      },
      security: {
        required_scopes: ['hcp:data:describe'],
        data_in: ['handle_ref'],
        data_out: ['metadata']
      },
      mcp: {
        tool_name: 'describe',
        tool: {
          name: 'describe',
          description: 'Return metadata and data classes for an HCP vault handle without releasing payload content.'
        }
      }
    },
    {
      id: `${providerId}.revoke`,
      version: '0.1.0',
      title: 'Revoke HCP Vault Handle',
      description: 'Revoke an HCP vault handle so its underlying payload can no longer be peeked or piped.',
      intents: ['revoke handle', 'delete handle'],
      input_schema: {
        type: 'object',
        required: ['handle'],
        properties: {
          handle: { type: 'string', description: 'The h://vault/... handle identifier.' },
          reason: { type: 'string', description: 'Reason for revocation.' }
        }
      },
      output_schema: { type: 'object' },
      effects: {
        kind: 'read',
        risk: 'low'
      },
      security: {
        required_scopes: ['hcp:data:revoke'],
        data_in: ['handle_ref'],
        data_out: ['revocation_receipt']
      },
      mcp: {
        tool_name: 'revoke',
        tool: {
          name: 'revoke',
          description: 'Revoke an HCP vault handle so its underlying payload can no longer be peeked or piped.'
        }
      }
    }
  ];

  return makeProvider({
    async manifest() {
      return {
        provider: {
          id: providerId,
          version: '0.1.0',
          title: 'HCP DataVault Tools',
          description: 'Built-in HCP DataVault inspection and revocation tools for offloaded MCP handles.'
        },
        capabilities
      };
    },
    async health() {
      return { status: 'ok' };
    },
    async resourceFor() {
      return 'vault:handles';
    },
    async invoke({ capability, input = {}, options = {} }) {
      const callerPrincipal = options.principal ?? defaultPrincipal;
      if (capability.id === `${providerId}.peek`) {
        const projection = {
          mode: input.mode ?? 'preview',
          ...(Array.isArray(input.redactions) ? { redactions: input.redactions } : {}),
          ...(Number.isInteger(input.max_bytes) && input.max_bytes > 0
            ? { max_bytes: input.max_bytes }
            : {})
        };
        const peeked = runtime.dataPeek(input.handle, projection, { principal: callerPrincipal });
        if (projection.max_bytes && projection.mode === 'full' && peeked.value !== undefined) {
          const text = typeof peeked.value === 'string' ? peeked.value : JSON.stringify(peeked.value, null, 2);
          const bounded = applyTransform(text, { max_bytes: projection.max_bytes });
          return { ...peeked, value: bounded, truncated: bounded.length < text.length };
        }
        return peeked;
      }
      if (capability.id === `${providerId}.describe`) {
        return runtime.dataDescribe(input.handle, { principal: callerPrincipal });
      }
      if (capability.id === `${providerId}.revoke`) {
        const owner = runtime.dataVault.get(input.handle).metadata?.principal ?? null;
        if (owner && owner !== callerPrincipal) {
          throw new HcpError('Handle revoke denied for principal', 'HANDLE_ACCESS_DENIED', {
            handle: input.handle,
            principal: callerPrincipal
          });
        }
        return runtime.dataRevoke(input.handle, input.reason ?? 'revoked_via_mcp_proxy');
      }
      throw new HcpError(`Unknown HCP vault capability: ${capability.id}`, 'METHOD_NOT_FOUND', {
        capability: capability.id
      });
    }
  });
}

async function wrapConfiguredServer(server, { workspace, fetchImpl }) {
  if (server.mcpServer) {
    return wrapMcpServerAsProvider({
      mcpServer: server.mcpServer,
      providerId: server.provider_id,
      title: server.title,
      version: server.version,
      capabilityOverrides: server.capability_overrides
    });
  }
  if (server.transportInstance) {
    return wrapMcpJsonRpcServerAsProvider({
      transport: server.transportInstance,
      protocolVersion: server.protocol_version,
      providerId: server.provider_id,
      title: server.title,
      version: server.version,
      capabilityOverrides: server.capability_overrides
    });
  }
  if (server.transport === 'http') {
    if (!server.origin) {
      throw new InvalidInputError(`HTTP MCP server '${server.id}' requires an origin URL`, { server });
    }
    return wrapMcpHttpServerAsProvider({
      origin: server.origin,
      path: server.path ?? '/mcp',
      headers: server.headers ?? {},
      fetchImpl,
      protocolVersion: server.protocol_version,
      providerId: server.provider_id,
      title: server.title,
      version: server.version,
      capabilityOverrides: server.capability_overrides
    });
  }
  if (!server.command) {
    throw new InvalidInputError(`Stdio MCP server '${server.id}' requires a command`, { server });
  }
  return wrapMcpStdioServerAsProvider({
    command: server.command,
    args: server.args ?? [],
    cwd: server.cwd ?? workspace,
    env: Object.keys(server.env ?? {}).length > 0 ? server.env : undefined,
    timeoutMs: server.timeout_ms,
    protocolVersion: server.protocol_version,
    providerId: server.provider_id,
    title: server.title,
    version: server.version,
    capabilityOverrides: server.capability_overrides
  });
}

function collectProviderGrantSpec(manifest, { mode = true } = {}) {
  const capabilities = manifest.capabilities ?? [];
  const filtered = mode === 'read_only'
    ? capabilities.filter((cap) => (cap.effects?.kind ?? 'read') === 'read')
    : capabilities;
  const capabilityIds = filtered.map((cap) => cap.id);
  const scopes = [...new Set(filtered.flatMap((cap) => cap.security?.required_scopes ?? []))];
  const resources = [...new Set(filtered.map((cap) => {
    if (cap.mcp?.tool_name) return defaultToolResource(cap.mcp.tool_name);
    if (cap.mcp?.resource) return defaultMcpResource(cap.mcp.resource);
    if (cap.mcp?.prompt_name) return defaultPromptResource(cap.mcp.prompt_name);
    return defaultToolResource(cap.id);
  }))];
  return {
    capabilities: capabilityIds,
    scopes,
    resources
  };
}

// Wraps the reference policy engine. Grant/scope/resource checks are never
// relaxed; the only thing this engine adds is the approval decision for
// write-class tools: pre-approved by an explicit policy.json grant
// (explicit mode) or globally (auto mode). In prompt mode nothing is
// pre-approved and the reference engine returns ask_approval.
export class McpProxyPolicyEngine extends DefaultPolicyEngine {
  constructor({ approvalMode = DEFAULT_MCP_PROXY_APPROVAL_MODE, ...options } = {}) {
    super(options);
    this.approvalMode = normalizeApprovalMode(approvalMode);
    this.preApproved = new Set();
  }

  preApprove(principal, capabilityId) {
    this.preApproved.add(`${principal}\u0000${capabilityId}`);
  }

  isPreApproved(principal, capabilityId) {
    if (this.approvalMode === 'auto') return true;
    if (this.approvalMode !== 'explicit') return false;
    return this.preApproved.has(`${principal}\u0000${capabilityId}`);
  }

  decide(context = {}) {
    const options = context.options ?? {};
    const capabilityId = context.capability?.id;
    if (options.approval?.approved !== true && capabilityId && this.isPreApproved(options.principal ?? null, capabilityId)) {
      return super.decide({
        ...context,
        options: {
          ...options,
          approval: { approved: true, by: `hcp.proxy.approval_mode:${this.approvalMode}` }
        }
      });
    }
    return super.decide(context);
  }
}

export async function createMcpProxyRuntime(policyInput = {}, {
  workspace = process.cwd(),
  serverId = null,
  principal: principalOverride = null,
  approval: approvalOverride = undefined,
  approvalMode: approvalModeOverride = undefined,
  auditLogPath: auditLogOverride = undefined,
  secretsPath = null,
  maxInlineBytes = undefined,
  interceptSecrets = undefined,
  offloadLargeOutputs = undefined,
  exposeVaultTools = undefined,
  fetchImpl = globalThis.fetch,
  env = process.env
} = {}) {
  const policy = await loadMcpProxyPolicy(policyInput, {
    workspace,
    secretsPath,
    env
  });

  const principal = principalOverride ?? policy.principal ?? DEFAULT_MCP_PROXY_PRINCIPAL;
  const approvalMode = approvalModeOverride !== undefined && approvalModeOverride !== null
    ? normalizeApprovalMode(approvalModeOverride)
    : policy.approval_mode;
  // Only `auto` carries a blanket approval; explicit/prompt never forward a
  // policy-level approval object that would silently bypass the gate.
  const approval = approvalOverride !== undefined
    ? approvalOverride
    : (approvalMode === 'auto' ? { approved: true, by: 'hcp.proxy.approval_mode:auto' } : null);
  const auditLogPath = auditLogOverride === false
    ? null
    : (typeof auditLogOverride === 'string' && auditLogOverride.trim()
        ? (path.isAbsolute(auditLogOverride) ? auditLogOverride : path.resolve(workspace, auditLogOverride))
        : policy.audit_log_path);

  const topOutputPolicy = normalizeOutputPolicy(policy.output_policy, {
    ...(maxInlineBytes !== undefined ? { max_inline_bytes: maxInlineBytes } : {}),
    ...(interceptSecrets !== undefined ? { intercept_secrets: interceptSecrets } : {}),
    ...(offloadLargeOutputs !== undefined ? { offload_large_outputs: offloadLargeOutputs } : {}),
    ...(exposeVaultTools !== undefined ? { expose_vault_tools: exposeVaultTools } : {})
  });

  const activeServers = policy.servers.filter((server) => {
    if (!server.enabled) return false;
    if (!serverId) return true;
    const requested = sanitizeId(serverId);
    return server.id === requested || server.provider_id === requested || server.provider_id === `mcp.${requested}`;
  });

  if (serverId && activeServers.length === 0) {
    throw new InvalidInputError(`MCP proxy server '${serverId}' was not found in policy`, {
      serverId,
      available: policy.servers.map((item) => item.id)
    });
  }

  const runtime = new HcpRuntime({
    workspace,
    includeDefaultProviders: policy.include_default_providers,
    auditLogPath,
    retention: policy.retention,
    policyEngine: new McpProxyPolicyEngine({ approvalMode })
  });
  const engine = runtime.policyEngine;

  const wrappedProviders = [];
  try {
    for (const server of activeServers) {
      const serverOutputPolicy = normalizeOutputPolicy(topOutputPolicy, server.output_policy ?? {});
      const rawProvider = await wrapConfiguredServer(server, { workspace, fetchImpl });
      const guardedProvider = wrapProviderWithOutputGuard(rawProvider, {
        runtime,
        principal,
        outputPolicy: serverOutputPolicy,
        capabilityOverrides: server.capability_overrides
      });
      await runtime.registerProvider(guardedProvider);
      wrappedProviders.push({
        server,
        provider: guardedProvider
      });

      const autoGrantMode = server.auto_grant !== undefined ? server.auto_grant : policy.auto_grant;
      if (autoGrantMode) {
        const manifest = runtime.providers.get(server.provider_id)?.manifest;
        if (manifest) {
          const spec = collectProviderGrantSpec(manifest, { mode: autoGrantMode });
          if (spec.capabilities.length > 0 && spec.scopes.length > 0) {
            runtime.grantCreate({
              principal,
              scopes: spec.scopes,
              resources: spec.resources,
              capabilities: spec.capabilities
            });
          }
        }
      }
    }

    if (topOutputPolicy.expose_vault_tools) {
      const vaultProvider = createMcpProxyVaultProvider(runtime, {
        defaultPrincipal: principal
      });
      await runtime.registerProvider(vaultProvider);
      runtime.grantCreate({
        principal,
        scopes: ['hcp:data:peek', 'hcp:data:describe', 'hcp:data:revoke'],
        resources: ['vault:handles'],
        capabilities: ['hcp.data.peek', 'hcp.data.describe', 'hcp.data.revoke']
      });
    }

    for (const grant of policy.grants) {
      const capabilities = Array.isArray(grant.capabilities) ? grant.capabilities.map(String) : [];
      if (capabilities.length === 0 || capabilities.includes('*')) {
        throw new InvalidInputError(
          'MCP proxy policy grants must list explicit capability ids (e.g. "mcp.github.create_issue"); wildcards are not supported',
          { grant }
        );
      }
      // Scopes and resources default to what the listed capabilities require,
      // so a policy author only has to name the tools being authorized.
      // Capabilities of servers not started by this proxy instance (for
      // example under `--server <id>`) are skipped.
      const registered = capabilities.filter((id) => runtime.capabilities.has(id));
      if (registered.length === 0) continue;
      const derived = collectProviderGrantSpec(
        { capabilities: registered.map((id) => runtime.capabilities.get(id).capability) },
        { mode: true }
      );
      const grantPrincipal = grant.principal ?? principal;
      runtime.grantCreate({
        principal: grantPrincipal,
        scopes: Array.isArray(grant.scopes) && grant.scopes.length > 0 ? grant.scopes : derived.scopes,
        resources: Array.isArray(grant.resources) && grant.resources.length > 0 ? grant.resources : derived.resources,
        capabilities: registered,
        ...(grant.expires_at ? { expires_at: grant.expires_at } : {})
      });
      if (grant.require_approval !== true) {
        for (const capabilityId of registered) engine.preApprove(grantPrincipal, capabilityId);
      }
    }

    if (policy.unresolved_secrets.length > 0) {
      runtime.auditEntries.push({
        type: 'MCP_PROXY_SECRET_UNRESOLVED',
        timestamp: new Date().toISOString(),
        principal,
        unresolved: policy.unresolved_secrets
      });
    }

    runtime.auditEntries.push({
      type: 'MCP_PROXY_STARTED',
      timestamp: new Date().toISOString(),
      principal,
      approval_mode: approvalMode,
      servers: activeServers.map((item) => ({
        id: item.id,
        provider_id: item.provider_id,
        transport: typeof item.transport === 'string' ? item.transport : 'custom'
      })),
      output_policy: topOutputPolicy,
      audit_log_path: auditLogPath
    });

    let closed = false;
    async function close() {
      if (closed) return { closed: true };
      closed = true;
      const results = [];
      for (const { server, provider } of wrappedProviders) {
        if (typeof provider.close === 'function') {
          try {
            results.push({ id: server.id, result: await provider.close() });
          } catch (error) {
            results.push({ id: server.id, error: error.message });
          }
        }
      }
      runtime.auditEntries.push({
        type: 'MCP_PROXY_STOPPED',
        timestamp: new Date().toISOString(),
        principal,
        servers: activeServers.map((item) => item.id)
      });
      return { closed: true, servers: results };
    }

    return {
      runtime,
      policy: {
        ...policy,
        output_policy: topOutputPolicy
      },
      principal,
      approval,
      approvalMode,
      auditLogPath,
      servers: activeServers,
      close
    };
  } catch (error) {
    for (const { provider } of wrappedProviders) {
      if (typeof provider.close === 'function') {
        await Promise.resolve(provider.close()).catch(() => {});
      }
    }
    throw error;
  }
}

export async function serveMcpProxy({
  policy = {},
  workspace = process.cwd(),
  serverId = null,
  principal = null,
  approval = undefined,
  approvalMode = undefined,
  requestStateAuthority = undefined,
  auditLogPath = undefined,
  secretsPath = null,
  maxInlineBytes = undefined,
  interceptSecrets = undefined,
  offloadLargeOutputs = undefined,
  exposeVaultTools = undefined,
  transport = 'stdio',
  host = '127.0.0.1',
  port = 0,
  protocolVersion = MCP_PROTOCOL_VERSION,
  scopeDiscovery = undefined,
  input = process.stdin,
  output = process.stdout,
  fetchImpl = globalThis.fetch,
  env = process.env
} = {}) {
  const proxy = await createMcpProxyRuntime(policy, {
    workspace,
    serverId,
    principal,
    approval,
    approvalMode,
    auditLogPath,
    secretsPath,
    maxInlineBytes,
    interceptSecrets,
    offloadLargeOutputs,
    exposeVaultTools,
    fetchImpl,
    env
  });

  // prompt mode delivers approvals through MCP elicitation using signed,
  // single-use MRTR request state; other modes keep the classic behaviour.
  const mrtrAuthority = requestStateAuthority !== undefined
    ? requestStateAuthority
    : (proxy.approvalMode === 'prompt' ? createRequestStateAuthority() : null);
  const serverInfo = { name: 'hcp-mcp-proxy', version: HCP_RUNTIME_VERSION };

  const effectiveScopeDiscovery = scopeDiscovery !== undefined
    ? Boolean(scopeDiscovery)
    : proxy.policy.scope_discovery;

  if (transport === 'http') {
    const httpServer = await serveJsonRpcHttp({
      runtime: proxy.runtime,
      host,
      port,
      mcp: {
        principal: proxy.principal,
        approval: proxy.approval,
        protocolVersion,
        scopeDiscovery: effectiveScopeDiscovery,
        requestStateAuthority: mrtrAuthority,
        serverInfo
      },
      mcpStateless: {
        principal: proxy.principal,
        approval: proxy.approval,
        scopeDiscovery: effectiveScopeDiscovery,
        requestStateAuthority: mrtrAuthority,
        serverInfo
      }
    });
    return {
      ...proxy,
      transport: 'http',
      origin: httpServer.origin,
      server: httpServer.server,
      async close() {
        await httpServer.close();
        return proxy.close();
      }
    };
  }

  const dispatcher = createMcpClientShimDispatcher(proxy.runtime, {
    principal: proxy.principal,
    approval: proxy.approval,
    protocolVersion,
    scopeDiscovery: effectiveScopeDiscovery,
    requestStateAuthority: mrtrAuthority,
    serverInfo
  });
  // serveMcpStdio resolves when the input stream ends.
  const served = serveMcpStdio({ runtime: proxy.runtime, dispatcher, input, output });

  if (input && typeof input.once === 'function') {
    input.once('close', () => {
      proxy.close().catch(() => {});
    });
  }

  return {
    ...proxy,
    transport: 'stdio',
    dispatcher,
    served,
    close() {
      return proxy.close();
    }
  };
}
