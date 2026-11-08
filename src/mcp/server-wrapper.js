import { InvalidInputError } from '../errors.js';
import { makeProvider } from '../provider-sdk.js';
import {
  MCP_PROTOCOL_VERSION,
  defaultMcpResource,
  defaultPromptResource,
  defaultToolResource,
  mcpDisplayFields,
  normalizePrompt,
  normalizeResource,
  normalizeResourceTemplate,
  normalizeTool,
  promptArgumentProperties,
  promptArgumentsArray,
  promptCapabilityId,
  resourceCapabilityId,
  sanitizeId,
  toolCapabilityId
} from './common.js';
import {
  createMcpHttpServerClient,
  createMcpJsonRpcServerClient,
  createMcpStdioServerClient
} from './server-client.js';

export async function wrapMcpJsonRpcServerAsProvider({
  transport,
  command,
  args = [],
  cwd = process.cwd(),
  env = undefined,
  timeoutMs = 5000,
  protocolVersion = MCP_PROTOCOL_VERSION,
  clientInfo,
  providerId = 'mcp.wire',
  title = 'Wrapped MCP JSON-RPC Server',
  version = '0.1.0',
  capabilityOverrides = {}
} = {}) {
  const mcpServer = transport
    ? createMcpJsonRpcServerClient({ transport, protocolVersion, clientInfo })
    : createMcpStdioServerClient({ command, args, cwd, env, timeoutMs, protocolVersion, clientInfo });
  return wrapMcpServerAsProvider({
    mcpServer,
    providerId,
    title,
    version,
    capabilityOverrides
  });
}

export async function wrapMcpStdioServerAsProvider({
  command,
  args = [],
  cwd = process.cwd(),
  env = undefined,
  timeoutMs = 5000,
  protocolVersion = MCP_PROTOCOL_VERSION,
  clientInfo,
  providerId = 'mcp.stdio',
  title = 'Wrapped MCP Stdio Server',
  version = '0.1.0',
  capabilityOverrides = {}
} = {}) {
  return wrapMcpJsonRpcServerAsProvider({
    command,
    args,
    cwd,
    env,
    timeoutMs,
    protocolVersion,
    clientInfo,
    providerId,
    title,
    version,
    capabilityOverrides
  });
}

export async function wrapMcpHttpServerAsProvider({
  origin,
  path = '/mcp',
  fetchImpl = globalThis.fetch,
  headers = {},
  sessionId = null,
  protocolVersion = MCP_PROTOCOL_VERSION,
  clientInfo,
  providerId = 'mcp.http',
  title = 'Wrapped MCP HTTP Server',
  version = '0.1.0',
  capabilityOverrides = {}
} = {}) {
  const mcpServer = createMcpHttpServerClient({
    origin,
    path,
    fetchImpl,
    headers,
    sessionId,
    protocolVersion,
    clientInfo
  });
  return wrapMcpServerAsProvider({
    mcpServer,
    providerId,
    title,
    version,
    capabilityOverrides
  });
}

export async function wrapMcpServerAsProvider({
  mcpServer,
  providerId = 'mcp.mock',
  title = 'Wrapped MCP Server',
  version = '0.1.0',
  capabilityOverrides = {}
} = {}) {
  if (!mcpServer) {
    throw new InvalidInputError('MCP server adapter requires an MCP-like server object', { mcpServer });
  }

  const hasTools = typeof mcpServer.listTools === 'function' || typeof mcpServer.callTool === 'function';
  if (hasTools && (typeof mcpServer.listTools !== 'function' || typeof mcpServer.callTool !== 'function')) {
    throw new InvalidInputError('MCP tool adapter requires both listTools() and callTool()', { mcpServer });
  }
  const hasResources = typeof mcpServer.listResources === 'function' || typeof mcpServer.readResource === 'function';
  if (hasResources && (typeof mcpServer.listResources !== 'function' || typeof mcpServer.readResource !== 'function')) {
    throw new InvalidInputError('MCP resource adapter requires both listResources() and readResource()', { mcpServer });
  }
  if (mcpServer.listResourceTemplates !== undefined && typeof mcpServer.listResourceTemplates !== 'function') {
    throw new InvalidInputError('MCP resource template adapter requires listResourceTemplates()', { mcpServer });
  }
  const hasPrompts = typeof mcpServer.listPrompts === 'function' || typeof mcpServer.getPrompt === 'function';
  if (hasPrompts && (typeof mcpServer.listPrompts !== 'function' || typeof mcpServer.getPrompt !== 'function')) {
    throw new InvalidInputError('MCP prompt adapter requires both listPrompts() and getPrompt()', { mcpServer });
  }

  const tools = hasTools ? (await mcpServer.listTools()).map(normalizeTool) : [];
  const resources = hasResources ? (await mcpServer.listResources()).map(normalizeResource) : [];
  const resourceTemplates = typeof mcpServer.listResourceTemplates === 'function'
    ? (await mcpServer.listResourceTemplates()).map(normalizeResourceTemplate)
    : [];
  const prompts = hasPrompts ? (await mcpServer.listPrompts()).map(normalizePrompt) : [];
  const providerIdSafe = sanitizeId(providerId);
  const capabilityToTool = new Map();
  const capabilityToResource = new Map();
  const capabilityToPrompt = new Map();

  const toolCapabilities = tools.map((tool) => {
    const capabilityId = toolCapabilityId(providerIdSafe, tool.name);
    capabilityToTool.set(capabilityId, tool);
    const override = capabilityOverrides[tool.name] ?? capabilityOverrides[capabilityId] ?? {};
    return {
      id: capabilityId,
      version: override.version ?? tool.version ?? version,
      title: override.title ?? tool.title ?? tool.name,
      description: override.description ?? tool.description ?? `Wrapped MCP tool ${tool.name}`,
      intents: override.intents ?? [tool.name, ...(tool.annotations?.intents ?? [])],
      input_schema: override.input_schema ?? tool.inputSchema ?? tool.input_schema ?? { type: 'object' },
      output_schema: override.output_schema ?? { type: 'object' },
      effects: {
        kind: 'read',
        risk: 'medium',
        ...(override.effects ?? {})
      },
      security: {
        required_scopes: [`mcp:${sanitizeId(tool.name)}:call`],
        data_in: ['external_content'],
        data_out: ['external_content'],
        ...(override.security ?? {})
      },
      mcp: {
        tool_name: tool.name,
        tool: {
          name: tool.name,
          description: tool.description ?? null,
          inputSchema: tool.inputSchema ?? tool.input_schema ?? { type: 'object' },
          outputSchema: tool.outputSchema ?? tool.output_schema ?? null,
          annotations: tool.annotations ?? null,
          execution: tool.execution ?? null,
          ...mcpDisplayFields(tool, ['title', 'icons'])
        }
      }
    };
  });
  const resourceCapabilities = resources.map((resource) => {
    const capabilityId = resourceCapabilityId(providerIdSafe, resource);
    capabilityToResource.set(capabilityId, resource);
    const override = capabilityOverrides[resource.uri] ?? capabilityOverrides[capabilityId] ?? {};
    const resourceKey = sanitizeId(resource.uri);
    return {
      id: capabilityId,
      version: override.version ?? resource.version ?? version,
      title: override.title ?? resource.name ?? resource.title ?? resource.uri,
      description: override.description ?? resource.description ?? `Wrapped MCP resource ${resource.uri}`,
      intents: override.intents ?? ['read resource', resource.uri, resource.name ?? ''],
      input_schema: override.input_schema ?? {
        type: 'object',
        properties: {}
      },
      output_schema: override.output_schema ?? { type: 'object' },
      effects: {
        kind: 'read',
        risk: 'low',
        ...(override.effects ?? {})
      },
      security: {
        required_scopes: [`mcp:resource:${resourceKey}:read`],
        data_in: ['resource_uri'],
        data_out: ['external_content'],
        ...(override.security ?? {})
      },
      mcp: {
        resource_uri: resource.uri,
        resource: {
          uri: resource.uri,
          name: resource.name ?? resource.uri,
          description: resource.description ?? null,
          ...mcpDisplayFields(resource)
        }
      }
    };
  });
  const promptCapabilities = prompts.map((prompt) => {
    const capabilityId = promptCapabilityId(providerIdSafe, prompt.name);
    capabilityToPrompt.set(capabilityId, prompt);
    const override = capabilityOverrides[prompt.name] ?? capabilityOverrides[capabilityId] ?? {};
    const promptKey = sanitizeId(prompt.name);
    return {
      id: capabilityId,
      version: override.version ?? prompt.version ?? version,
      title: override.title ?? prompt.title ?? prompt.name,
      description: override.description ?? prompt.description ?? `Wrapped MCP prompt ${prompt.name}`,
      intents: override.intents ?? ['get prompt', prompt.name, ...(prompt.arguments ?? []).map((arg) => arg.name ?? '')],
      input_schema: override.input_schema ?? {
        type: 'object',
        properties: {
          arguments: {
            type: 'object',
            properties: promptArgumentProperties(prompt)
          }
        }
      },
      output_schema: override.output_schema ?? { type: 'object' },
      effects: {
        kind: 'read',
        risk: 'low',
        ...(override.effects ?? {})
      },
      security: {
        required_scopes: [`mcp:prompt:${promptKey}:get`],
        data_in: ['prompt_arguments'],
        data_out: ['prompt_template'],
        ...(override.security ?? {})
      },
      mcp: {
        prompt_name: prompt.name,
        prompt: {
          name: prompt.name,
          description: prompt.description ?? null,
          arguments: promptArgumentsArray(prompt),
          ...mcpDisplayFields(prompt, ['title', 'icons'])
        }
      }
    };
  });
  const capabilities = [...toolCapabilities, ...resourceCapabilities, ...promptCapabilities];

  const provider = makeProvider({
    async manifest() {
      return {
        provider: {
          id: providerIdSafe,
          version,
          title,
          description: 'HCP provider wrapper around an MCP-like server object.'
        },
        capabilities,
        mcp: {
          resource_templates: resourceTemplates.map((template) => ({ ...template }))
        }
      };
    },

    async health() {
      if (typeof mcpServer.health === 'function') return mcpServer.health();
      return { status: 'ok' };
    },

    async resourceFor({ capability }) {
      const tool = capabilityToTool.get(capability.id);
      if (tool) return defaultToolResource(tool.name);
      const resource = capabilityToResource.get(capability.id);
      if (resource) return defaultMcpResource(resource);
      const prompt = capabilityToPrompt.get(capability.id);
      if (prompt) return defaultPromptResource(prompt.name);
      return defaultToolResource(capability.id);
    },

    async invoke({ capability, input }) {
      const tool = capabilityToTool.get(capability.id);
      if (tool) {
        return mcpServer.callTool({
          name: tool.name,
          arguments: input
        });
      }
      const resource = capabilityToResource.get(capability.id);
      if (resource) {
        return mcpServer.readResource({
          uri: resource.uri
        });
      }
      const prompt = capabilityToPrompt.get(capability.id);
      if (prompt) {
        return mcpServer.getPrompt({
          name: prompt.name,
          arguments: input.arguments ?? input
        });
      }
      throw new InvalidInputError(`Unknown wrapped MCP capability: ${capability.id}`, { capability: capability.id });
    }
  });

  if (typeof mcpServer.close === 'function') {
    return {
      ...provider,
      close() {
        return mcpServer.close();
      }
    };
  }

  return provider;
}
