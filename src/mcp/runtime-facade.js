import { HcpError, InvalidInputError } from '../errors.js';
import { requestDigest, toInputRequiredResult } from '../mrtr.js';
import {
  MCP_CLIENT_CAPABILITIES_META_KEY,
  MCP_LIST_PAGE_SIZE,
  isMcpToolResult,
  isObject,
  mcpDisplayFields,
  mcpTaskId,
  relatedTaskMeta,
  toMcpTask
} from './common.js';

export function createMcpRuntimeFacade(runtime, {
  principal = null,
  approval = null,
  scopeDiscovery = false,
  requestStateAuthority = null
} = {}) {
  // Present when the deployment speaks MRTR. Without it the facade keeps the
  // previous behaviour of reporting a waiting task as an error result.
  const mrtr = requestStateAuthority;
  function capabilityDiscoveryLimit() {
    return Math.max(runtime.capabilities?.size ?? 0, MCP_LIST_PAGE_SIZE);
  }

  // With scopeDiscovery enabled, catalog listings become a function of the
  // authorization presented, as the 2026-07-28 revision permits: a principal
  // sees only capabilities it could hold authority for, and an anonymous
  // request sees only capabilities that require no scopes. It is opt-in
  // because anonymous local deployments legitimately list the full catalog,
  // and enabling it unconditionally would deny those.
  async function listFullCapabilities() {
    const results = await runtime.capSearch(
      '',
      { limit: capabilityDiscoveryLimit() },
      scopeDiscovery ? { principal, scope_discovery: true } : {}
    );
    return results.map((result) => runtime.capDescribe(result.capability, 'full'));
  }

  function listProviderManifests() {
    return [...runtime.providers.values()].map((entry) => entry.manifest);
  }

  async function runCapability(capabilityId, input = {}, options = {}) {
    const task = await runtime.taskStart(capabilityId, input, {
      principal,
      approval: approval ?? undefined,
      ...options
    });
    if (task.status !== 'COMPLETED') {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: task.status,
              error: task.error ?? null,
              policy_decisions: task.policy_decisions
            })
          }
        ],
        hcp_task: task
      };
    }
    return {
      result: task.result,
      hcp_task: task
    };
  }

  return {
    async listTools() {
      const capabilities = await listFullCapabilities();
      return capabilities.map((capability) => {
        const toolMetadata = capability.mcp?.tool ?? {};
        const mcpAnnotations = isObject(toolMetadata.annotations) ? toolMetadata.annotations : {};
        return {
          name: capability.id,
          title: toolMetadata.title ?? capability.title,
          description: toolMetadata.description ?? capability.description ?? capability.title,
          inputSchema: toolMetadata.inputSchema ?? capability.input_schema,
          ...(toolMetadata.outputSchema ? { outputSchema: toolMetadata.outputSchema } : {}),
          ...mcpDisplayFields(toolMetadata, ['icons']),
          ...(toolMetadata.execution ? { execution: toolMetadata.execution } : {}),
          annotations: {
            ...mcpAnnotations,
            hcp_effect: capability.effects?.kind,
            hcp_risk: capability.effects?.risk
          }
        };
      });
    },

    async callTool({ name, arguments: input = {}, task = undefined, inputResponses = undefined, requestState = undefined, _meta = {} }) {
      const taskOptions = task !== undefined ? { mcp_task: isObject(task) ? { ...task } : {} } : {};

      const digest = requestDigest('tools/call', { name, arguments: input, ...(task === undefined ? {} : { task }) });
      const requireElicitation = () => {
        const elicitation = _meta[MCP_CLIENT_CAPABILITIES_META_KEY]?.elicitation;
        if (!isObject(elicitation) || (Object.keys(elicitation).length > 0 && !isObject(elicitation.form))) {
          throw new HcpError('Client must declare form elicitation support for approval', 'MISSING_REQUIRED_CLIENT_CAPABILITY', { requiredCapabilities: { elicitation: { form: {} } } });
        }
      };
      let resumedApproval;
      if (mrtr && (inputResponses !== undefined || requestState !== undefined)) {
        const claims = mrtr.verify(requestState, { principal, digest, consume: false });
        requireElicitation();
        if (inputResponses !== undefined && !isObject(inputResponses)) {
          throw new InvalidInputError('MRTR inputResponses must be a response map');
        }
        const response = inputResponses?.[claims.input_id];
        if (response === undefined) {
          return toInputRequiredResult({ capability: name }, requestState, claims.input_id);
        }
        if (!isObject(response) || !['accept', 'decline', 'cancel'].includes(response.action) ||
            (response.action === 'accept' && (!isObject(response.content) || typeof response.content.approved !== 'boolean'))) {
          throw new InvalidInputError('MRTR approval response must be a valid elicitation result');
        }
        // Validation and consumption are synchronous: concurrent resumptions
        // cannot both cross this point before an asynchronous provider effect.
        mrtr.verify(requestState, { principal, digest });
        resumedApproval = { approved: response.action === 'accept' && response.content.approved === true, by: claims.sub };
      }

      const run = await runCapability(
        name,
        input,
        resumedApproval === undefined ? taskOptions : { ...taskOptions, approval: resumedApproval }
      );

      if (mrtr && task === undefined && resumedApproval === undefined) {
        const status = run.hcp_task?.status;
        if (status === 'WAITING_APPROVAL') {
          requireElicitation();
          return toInputRequiredResult(
            { ...run.hcp_task, capability: name },
            mrtr.mint({
              principal,
              capability: name,
              digest,
              inputId: run.hcp_task.task_id
            })
          );
        }
      }
      if (task !== undefined) {
        return {
          task: toMcpTask(run.hcp_task),
          _meta: {
            'io.modelcontextprotocol/model-immediate-response': `Task ${run.hcp_task.task_id} accepted by HCP runtime.`
          },
          hcp_task: run.hcp_task
        };
      }
      if (run.isError) return run;
      if (isMcpToolResult(run.result)) {
        return {
          ...run.result,
          hcp_task: run.hcp_task
        };
      }
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(run.result)
          }
        ],
        hcp_task: run.hcp_task
      };
    },

    async listTasks(filter = {}) {
      return runtime.taskList(filter, { principal }).map(toMcpTask);
    },

    async getTask(params = {}) {
      return toMcpTask(runtime.taskSnapshot(mcpTaskId(params)));
    },

    async taskResult(params = {}) {
      const taskId = mcpTaskId(params);
      const snapshot = runtime.taskSnapshot(taskId);
      const result = runtime.taskResult(taskId, params.projection ?? {}, { principal });
      if (result.status !== 'COMPLETED') {
        return {
          task: toMcpTask(snapshot),
          hcp_task: snapshot
        };
      }
      const metadata = relatedTaskMeta(snapshot);
      if (isMcpToolResult(result.result)) {
        return {
          ...result.result,
          _meta: {
            ...(isObject(result.result._meta) ? result.result._meta : {}),
            ...metadata
          },
          hcp_task: snapshot
        };
      }
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result.result)
          }
        ],
        isError: false,
        _meta: metadata,
        hcp_task: snapshot
      };
    },

    async cancelTask(params = {}) {
      return toMcpTask(runtime.taskCancel(mcpTaskId(params), params.reason ?? 'cancelled'));
    },

    async listResources() {
      const capabilities = await listFullCapabilities();
      return capabilities
        .filter((capability) => capability.mcp?.resource_uri)
        .map((capability) => ({
          uri: capability.mcp.resource_uri,
          name: capability.mcp.resource?.name ?? capability.title ?? capability.id,
          description: capability.mcp.resource?.description ?? capability.description ?? null,
          ...mcpDisplayFields(capability.mcp.resource),
          hcp_capability: capability.id
        }));
    },

    async listResourceTemplates() {
      const manifests = listProviderManifests();
      return manifests.flatMap((manifest) => (
        manifest.mcp?.resource_templates ?? []
      ).map((template) => ({
        uriTemplate: template.uriTemplate,
        name: template.name ?? template.uriTemplate,
        description: template.description ?? null,
        ...mcpDisplayFields(template, ['title', 'mimeType', 'icons', 'annotations']),
        mimeType: template.mimeType ?? template.mime_type ?? null,
        hcp_provider: manifest.provider.id
      })));
    },

    async readResource({ uri }) {
      const capabilities = await listFullCapabilities();
      const capability = capabilities.find((item) => item.mcp?.resource_uri === uri);
      if (!capability) {
        throw new HcpError(`Unknown MCP resource URI: ${uri}`, 'NOT_FOUND', { uri });
      }
      const run = await runCapability(capability.id, {});
      if (run.isError) return run;
      return {
        ...run.result,
        hcp_task: run.hcp_task
      };
    },

    async listPrompts() {
      const capabilities = await listFullCapabilities();
      return capabilities
        .filter((capability) => capability.mcp?.prompt_name)
        .map((capability) => ({
          name: capability.mcp.prompt_name,
          description: capability.mcp.prompt?.description ?? capability.description ?? null,
          arguments: capability.mcp.prompt?.arguments ?? [],
          ...mcpDisplayFields(capability.mcp.prompt, ['title', 'icons']),
          hcp_capability: capability.id
        }));
    },

    async getPrompt({ name, arguments: input = {} }) {
      const capabilities = await listFullCapabilities();
      const capability = capabilities.find((item) => item.mcp?.prompt_name === name);
      if (!capability) {
        throw new HcpError(`Unknown MCP prompt: ${name}`, 'NOT_FOUND', { name });
      }
      const run = await runCapability(capability.id, { arguments: input });
      if (run.isError) return run;
      return {
        ...run.result,
        hcp_task: run.hcp_task
      };
    },

    async complete({ ref = {}, argument = {} }) {
      const rawValue = String(argument.value ?? '').toLowerCase();
      if (ref.type === 'ref/resource') {
        const resources = await this.listResources();
        const values = resources
          .map((resource) => resource.uri)
          .filter((uri) => uri.toLowerCase().includes(rawValue))
          .slice(0, 100);
        return {
          completion: {
            values,
            total: values.length,
            hasMore: false
          }
        };
      }

      if (ref.type === 'ref/prompt') {
        const prompts = await this.listPrompts();
        if (!ref.name) {
          const values = prompts
            .map((prompt) => prompt.name)
            .filter((name) => name.toLowerCase().includes(rawValue))
            .slice(0, 100);
          return {
            completion: {
              values,
              total: values.length,
              hasMore: false
            }
          };
        }

        const prompt = prompts.find((item) => item.name === ref.name);
        if (!prompt) {
          throw new HcpError(`Unknown MCP prompt for completion: ${ref.name}`, 'NOT_FOUND', { name: ref.name });
        }
        const values = (prompt.arguments ?? [])
          .map((argument) => argument.name)
          .filter((name) => name.toLowerCase().includes(rawValue))
          .slice(0, 100);
        return {
          completion: {
            values,
            total: values.length,
            hasMore: false
          }
        };
      }

      throw new InvalidInputError('MCP completion ref must be ref/resource or ref/prompt', { ref });
    }
  };
}
