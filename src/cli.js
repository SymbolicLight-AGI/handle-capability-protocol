#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { cwd, execPath } from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  HcpRuntime,
  HcpJsonRpcClient,
  backupMcpConfig,
  buildApprovalSummary,
  createDefaultMcpProxyPolicy,
  createFilesystemProvider,
  createHcpJsonRpcDispatcher,
  createInMemoryJsonRpcTransport,
  createLocalManifestRegistry,
  doctorMcpConfig,
  exportMcpConfig,
  explainAuditTrace,
  importMcpConfig,
  inspectMcpConfigTargets,
  protectMcpClientConfig,
  readAuditLogEntries,
  restoreMcpClientConfig,
  scanMcpServerCommand,
  secretizeMcpConfig,
  serveMcpProxy,
  tailAuditLogEntries,
  validateRegistryManifest,
  serveJsonRpcHttp,
  serveJsonRpcStdio,
  serveMcpStdio,
  writeMcpClientConfig,
  wrapMcpHttpServerAsProvider,
  wrapMcpStdioServerAsProvider
} from './index.js';
import { matchesAuditFilter } from './core/matching.js';

const CLI_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(CLI_DIR, '../..');
const CONFORMANCE_CLI = resolve(REPO_ROOT, 'packages/hcp-conformance/src/cli.js');

async function makeRuntime(workspace = cwd()) {
  const runtime = new HcpRuntime();
  await runtime.registerProvider(createFilesystemProvider({ workspace }));
  return runtime;
}

function print(value) {
  console.log(JSON.stringify(value, null, 2));
}

function parseJson(value, fallback = {}) {
  if (value === undefined) return fallback;
  return JSON.parse(value);
}

async function parseJsonOrFile(value, fallback = {}) {
  if (value === undefined) return fallback;
  if (/^[\s]*[\[{]/.test(value)) return JSON.parse(value);
  return JSON.parse(await readFile(value, 'utf8'));
}

function parseTargetOption(args, defaultTarget = 'generic') {
  const targetIndex = args.indexOf('--target');
  if (targetIndex !== -1) return args[targetIndex + 1] ?? defaultTarget;
  return args.find((arg) => arg && arg !== '--target') ?? defaultTarget;
}

function optionValue(args, name, fallback = null) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1] ?? fallback;
}

function hasFlag(args, name) {
  return args.includes(name);
}

async function writeJsonFile(filePath, value) {
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return {
    path: filePath,
    bytes: Buffer.byteLength(JSON.stringify(value, null, 2), 'utf8') + 1
  };
}

async function writeTextFile(filePath, value) {
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, value, 'utf8');
  return {
    path: filePath,
    bytes: Buffer.byteLength(value, 'utf8')
  };
}

function parseCallArgs(rest) {
  const maybeParams = rest[0];
  if (maybeParams && /^[\s]*[\[{]/.test(maybeParams)) {
    return {
      params: JSON.parse(maybeParams),
      workspace: rest[1] ?? cwd()
    };
  }
  return {
    params: {},
    workspace: maybeParams ?? cwd()
  };
}

function runPassthroughNode(script, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(execPath, [script, ...args], {
      cwd: options.cwd ?? REPO_ROOT,
      windowsHide: true
    });
    child.stdout.on('data', (chunk) => {
      process.stdout.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      process.stderr.write(chunk);
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolvePromise(code ?? 1);
    });
  });
}

function maxSeverity(values = []) {
  const rank = { low: 1, medium: 2, high: 3 };
  return values.reduce((current, value) => (
    (rank[value] ?? 0) > (rank[current] ?? 0) ? value : current
  ), 'low');
}

function severityValue(value) {
  return { low: 1, medium: 2, high: 3 }[value] ?? 0;
}

function markdownCell(value) {
  return String(value ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, '<br>');
}

function markdownList(values = []) {
  return values.length > 0 ? values.join(', ') : 'none';
}

function summarizeExportTarget(config, target) {
  const exported = exportMcpConfig(config, { target });
  const servers = exported.mcpServers
    ? Object.keys(exported.mcpServers)
    : (config.servers ?? []).map((server) => server.id);
  return {
    target,
    format: exported.format ?? 'json',
    server_count: servers.length,
    server_ids: servers,
    managed_block: typeof exported.toml === 'string' ? /BEGIN HCP-MANAGED MCP SERVERS/.test(exported.toml) : false,
    notes: exported.notes ?? []
  };
}

function normalizeGovernanceConfig(config, source) {
  if (config.kind !== 'hcp.mcp.governance_config') {
    return importMcpConfig(config, { source, target: 'generic' });
  }
  return {
    ...config,
    source: config.source ?? source,
    servers: (config.servers ?? []).map((server) => ({
      ...server,
      risk: scanMcpServerCommand(server)
    }))
  };
}

async function buildMcpDoctorReport(configFile, options = {}) {
  const workspace = options.workspace ?? cwd();
  const config = await parseJsonOrFile(configFile);
  const imported = normalizeGovernanceConfig(config, configFile);
  const configDoctor = doctorMcpConfig(imported, { source: configFile });
  const discovery = await inspectMcpConfigTargets({ workspace });
  const exportTargets = ['cursor', 'claude', 'codex'].map((target) => summarizeExportTarget(imported, target));
  const serverRisks = configDoctor.servers.map((server) => ({
    id: server.id,
    transport: server.transport,
    risk: server.risk,
    env_refs: (server.env_refs ?? []).map((entry) => ({
      name: entry.name,
      ref: entry.expression ?? entry.ref ?? null,
      sensitive: entry.sensitive === true
    })),
    findings: server.findings ?? []
  }));
  const focusServer = serverRisks.reduce((selected, server) => (
    !selected || severityValue(server.risk) > severityValue(selected.risk) ? server : selected
  ), null);
  const highest = maxSeverity(serverRisks.map((server) => server.risk));
  const sensitiveEnvKeys = [...new Set(serverRisks.flatMap((server) => server.env_refs.map((entry) => entry.name)))].sort();
  const approvalSummary = focusServer ? buildApprovalSummary({
    principal: options.principal ?? 'user:mcp-operator',
    capability: `mcp.server.${focusServer.id}.enable`,
    resource: `mcp:${focusServer.id}`,
    required_scopes: [`mcp:${focusServer.id}:use`],
    matched_grant_ids: [],
    decision: focusServer.risk === 'high' ? 'review_required' : 'allow_after_review',
    reason: focusServer.risk === 'high' ? 'HIGH_RISK_MCP_SERVER' : 'MCP_SERVER_REVIEW',
    approval: { required: true, present: false }
  }, {
    id: `mcp.server.${focusServer.id}.enable`,
    effects: { kind: 'local_server_connect', risk: focusServer.risk }
  }) : null;

  return {
    kind: 'hcp.mcp.doctor_report',
    source: configFile,
    workspace,
    summary: {
      total_servers: configDoctor.total_servers,
      highest_risk: highest,
      high_risk_servers: configDoctor.risk_counts.high ?? 0,
      medium_risk_servers: configDoctor.risk_counts.medium ?? 0,
      low_risk_servers: configDoctor.risk_counts.low ?? 0,
      sensitive_env_keys: sensitiveEnvKeys,
      raw_secret_values_printed: false
    },
    config_doctor: configDoctor,
    server_risks: serverRisks,
    config_targets: {
      workspace: discovery.workspace,
      targets: discovery.targets.map((target) => ({
        target: target.target,
        scope: target.scope,
        format: target.format,
        path: target.path,
        exists: target.exists,
        write_supported: target.write_supported
      }))
    },
    export_targets: exportTargets,
    approval_summary_server_id: focusServer?.id ?? null,
    approval_summary: approvalSummary,
    explain_commands: {
      policy_explain: `hcp policy explain filesystem.file.read '{"path":"README.md"}' '{"principal":"user:mcp-operator"}' ${workspace}`,
      audit_explain: `hcp audit explain filesystem.file.read '{"path":"README.md"}' '{"principal":"user:mcp-operator","grant":true}' ${workspace}`,
      approval_summary: `hcp approval summary filesystem.file.write '{"path":"out.md","content":"hello"}' '{"principal":"user:mcp-operator","grant":true}' ${workspace}`
    },
    next_steps: [
      'Pin package-runner MCP server versions before sharing the config.',
      'Move raw secret values to environment references or a team secret manager.',
      'Use hcp mcp config write with --dry-run before writing client configs.',
      'Use policy explain, approval summary, and audit explain for runtime actions that touch files or external systems.'
    ]
  };
}

function renderMcpDoctorMarkdown(report) {
  const lines = [
    '# HCP MCP Governance Doctor Report',
    '',
    '## Summary',
    '',
    `- Source config: \`${report.source}\``,
    `- Workspace: \`${report.workspace}\``,
    `- MCP servers: ${report.summary.total_servers}`,
    `- Highest risk: ${report.summary.highest_risk}`,
    `- Risk counts: high=${report.summary.high_risk_servers}, medium=${report.summary.medium_risk_servers}, low=${report.summary.low_risk_servers}`,
    `- Sensitive env keys converted to references: ${markdownList(report.summary.sensitive_env_keys.map((key) => `\`${key}\``))}`,
    `- Raw secret values printed: ${report.summary.raw_secret_values_printed ? 'yes' : 'no'}`,
    '',
    '## Server Risk',
    '',
    '| Server | Transport | Risk | Env refs | Findings |',
    '| --- | --- | --- | --- | --- |'
  ];

  for (const server of report.server_risks) {
    const findings = server.findings ?? [];
    lines.push(`| ${markdownCell(server.id)} | ${markdownCell(server.transport)} | ${markdownCell(server.risk)} | ${markdownCell(markdownList(server.env_refs.map((entry) => entry.name)))} | ${markdownCell(markdownList(findings.map((finding) => `${finding.id}(${finding.severity})`)))} |`);
  }

  lines.push('', '## Findings', '');
  for (const server of report.server_risks) {
    lines.push(`### ${server.id}`, '');
    for (const finding of server.findings ?? []) {
      lines.push(`- **${finding.severity}** \`${finding.id}\`: ${finding.message}`);
      lines.push(`  Recommendation: ${finding.recommendation}`);
    }
    lines.push('');
  }

  lines.push(
    '## Config Targets',
    '',
    '| Target | Scope | Format | Exists | Path |',
    '| --- | --- | --- | --- | --- |'
  );
  for (const target of report.config_targets.targets) {
    lines.push(`| ${markdownCell(target.target)} | ${markdownCell(target.scope)} | ${markdownCell(target.format)} | ${target.exists ? 'yes' : 'no'} | \`${markdownCell(target.path)}\` |`);
  }

  lines.push(
    '',
    '## Export Plan',
    '',
    '| Target | Format | Server count | Managed block | Notes |',
    '| --- | --- | ---: | --- | --- |'
  );
  for (const target of report.export_targets) {
    lines.push(`| ${markdownCell(target.target)} | ${markdownCell(target.format)} | ${target.server_count} | ${target.managed_block ? 'yes' : 'no'} | ${markdownCell(markdownList(target.notes))} |`);
  }

  if (report.approval_summary) {
    lines.push(
      '',
      '## Approval Summary Shape',
      '',
      `Server: \`${report.approval_summary_server_id ?? report.approval_summary.resource ?? 'unknown'}\``,
      '',
      '```text',
      report.approval_summary.text,
      '```'
    );
  }

  lines.push(
    '',
    '## Policy / Audit Explain Commands',
    '',
    '```bash',
    report.explain_commands.policy_explain,
    report.explain_commands.approval_summary,
    report.explain_commands.audit_explain,
    '```',
    '',
    '## Recommended Next Steps',
    ''
  );
  for (const step of report.next_steps) {
    lines.push(`- ${step}`);
  }
  lines.push('');
  return lines.join('\n');
}

async function createLocalGrantForCapability(runtime, capabilityId, input, options, grantOption) {
  if (!grantOption) return null;
  const explanation = await runtime.policyExplain(capabilityId, input, options);
  const grantInput = typeof grantOption === 'object' && grantOption !== null ? grantOption : {};
  return runtime.grantCreate({
    principal: grantInput.principal ?? options.principal,
    scopes: grantInput.scopes ?? explanation.required_scopes,
    resources: grantInput.resources ?? [explanation.resource].filter(Boolean),
    capabilities: grantInput.capabilities ?? [capabilityId],
    expires_at: grantInput.expires_at
  });
}

async function runLocalTask({ capabilityId, input, options, workspace, resolveResult = true }) {
  const runtime = await makeRuntime(workspace);
  const taskOptions = { ...options };
  const grantOption = taskOptions.grant;
  delete taskOptions.grant;

  const grant = await createLocalGrantForCapability(runtime, capabilityId, input, taskOptions, grantOption);
  const task = await runtime.taskStart(capabilityId, input, taskOptions);
  const output = {
    grant,
    task,
    trace: task.task_id ? runtime.auditGetTrace(task.task_id) : null
  };

  if (resolveResult) {
    let result = null;
    if (task.task_id) {
      try {
        result = runtime.taskResult(
          task.task_id,
          { resolve_handle: true, mode: taskOptions.result_mode ?? 'preview' },
          { principal: taskOptions.principal }
        );
      } catch (error) {
        result = {
          error: {
            code: error.code ?? error.name,
            message: error.message,
            details: error.details ?? {}
          }
        };
      }
    }
    output.result = result;
  }

  return output;
}

async function runMcpWrappedProviderSmoke({
  provider,
  checks,
  providerId,
  workspace
}) {
  const runtime = await makeRuntime(workspace);
  try {
    await runtime.registerProvider(provider);
    const manifest = await provider.manifest();
    const capabilityId = checks.capability ?? manifest.capabilities?.[0]?.id;
    const input = checks.input ?? {};
    const options = {
      principal: checks.principal ?? 'user:mcp-wrapper',
      approval: checks.approval
    };
    if (checks.grant !== false) {
      runtime.grantCreate({
        principal: options.principal,
        scopes: checks.scopes ?? checks.required_scopes ?? manifest.capabilities
          ?.find((capability) => capability.id === capabilityId)
          ?.security?.required_scopes ?? [],
        resources: checks.resources ?? [checks.resource ?? `mcp:${capabilityId.split('.').at(-1)}`],
        capabilities: checks.capabilities ?? [capabilityId],
        expires_at: checks.expires_at
      });
    }
    const task = await runtime.taskStart(capabilityId, input, options);
    return {
      provider_id: providerId,
      capability_id: capabilityId,
      manifest,
      task,
      trace: task.task_id ? runtime.auditGetTrace(task.task_id) : null
    };
  } finally {
    await provider?.close?.();
  }
}

async function runMcpWrapStdioSmoke({
  providerId,
  checks,
  command,
  args,
  workspace,
  timeoutMs = 5000
}) {
  const provider = await wrapMcpStdioServerAsProvider({
    command,
    args,
    providerId,
    timeoutMs
  });
  return runMcpWrappedProviderSmoke({ provider, checks, providerId, workspace });
}

async function runMcpWrapHttpSmoke({
  providerId,
  checks,
  origin,
  path = '/mcp',
  workspace
}) {
  const provider = await wrapMcpHttpServerAsProvider({
    origin,
    path,
    providerId
  });
  return runMcpWrappedProviderSmoke({ provider, checks, providerId, workspace });
}

async function inspectDevWorkspace(workspace) {
  const runtime = await makeRuntime(workspace);
  const runtimeSummary = await runtime.inspectRuntime();
  const capabilities = await runtime.capSearch('', { limit: 20 });
  const manifestFixtureFromRuntime = '../docs/examples/local-filesystem-provider.manifest.json';
  const manifestFixtureFromRepo = 'docs/examples/local-filesystem-provider.manifest.json';
  return {
    workspace,
    runtime: runtimeSummary,
    capabilities,
    quickstart: {
      manifest_fixture_from_runtime: manifestFixtureFromRuntime,
      manifest_fixture_from_repo: manifestFixtureFromRepo,
      local_registry: './.hcp-registry',
      commands: [
        `hcp manifest validate ${manifestFixtureFromRuntime}`,
        `hcp registry publish --local ${manifestFixtureFromRuntime} ./.hcp-registry`,
        `hcp conformance registry --local ./.hcp-registry ${manifestFixtureFromRepo} '{"providerId":"local.filesystem","capabilityId":"filesystem.file.read","scope":"filesystem:read","effect":"read","risk":"low","maxRisk":"medium","expectedDiscoveryCount":2,"transport":"stdio"}'`
      ]
    },
    commands: [
      'hcp inspect runtime [workspace]',
      'hcp inspect provider [provider-id] [workspace]',
      'hcp run <capability-id> <json-input> <json-options> [workspace]',
      'hcp task watch <capability-id> <json-input> <json-options> [workspace]',
      'hcp trace <capability-id> <json-input> <json-options> [workspace]',
      'hcp policy explain <capability-id> <json-input> [json-options] [workspace]',
      'hcp policy decide <json-request> [workspace]',
      'hcp data peek <source-capability-id> <json-source-input> <json-options> [workspace]',
      'hcp data pipe --dry-run <source-capability-id> <json-source-input> <target-capability-id> <json-mapping> <json-options> [workspace]',
      'hcp audit trace <capability-id> <json-input> <json-options> [workspace]',
      'hcp audit explain <capability-id> <json-input> <json-options> [workspace]',
      'hcp audit report <capability-id> <json-input> <json-options> <out-file> [workspace]',
      'hcp approval summary <capability-id> <json-input> <json-options> [workspace]',
      'hcp mcp config discover [workspace]',
      'hcp mcp config write <mcp-or-hcp-config.json> --target cursor|claude|codex [--scope user|workspace] [--path file] [--protect] [--dry-run|--yes]',
      'hcp mcp config protect [mcp-config.json] --target cursor|claude|codex [--scope user|workspace] [--path file] [--approval-mode explicit|prompt|auto] [--dry-run|--yes]',
      'hcp mcp config restore --target cursor|claude|codex [--scope user|workspace] [--path file] [--dry-run|--yes]',
      'hcp mcp config backup <config-path>',
      'hcp mcp config secretize <mcp-config.json> [workspace]',
      'hcp mcp proxy [--config .hcp/policy.json] [--server id] [--transport stdio|http] [--approval-mode explicit|prompt|auto] [-- <command> <args...>]',
      'hcp mcp import-config <mcp-config.json> [--target cursor|claude|codex]',
      'hcp mcp config export <hcp-config.json> [--target cursor|claude|codex]',
      'hcp mcp doctor <mcp-or-hcp-config.json> [--format markdown|json] [--out report.md] [--workspace path]',
      'hcp mcp config doctor <mcp-or-hcp-config.json>',
      'hcp mcp risk-scan <json-server-or-config-file>',
      'hcp mcp expose-runtime <stdio|http> [workspace] [principal-or-port]',
      'hcp mcp wrap-server <stdio|http> <provider-id> <json-checks> <command-or-origin> [args-or-path]',
      'hcp mcp wrap-stdio <provider-id> <json-checks> <command> [args...]',
      'hcp mcp wrap-http <provider-id> <json-checks> <origin> [path]',
      'hcp conformance runtime --self-test',
      'hcp conformance runtime --stdio-check <json-checks> <command> [args...]',
      'hcp conformance runtime --http-check <json-checks> <origin>',
      'hcp conformance provider --stdio-behavior <json-checks> <command> [args...]',
      'hcp conformance provider --http-behavior <json-checks> <origin>',
      'hcp conformance client --stdio-check <json-checks> <command> [args...]',
      'hcp conformance client --http-check <json-checks> <origin>',
      'hcp conformance readiness --self-test',
      'hcp conformance readiness --provider-lifecycle <provider-lifecycle.json>',
      'hcp conformance readiness --sdk-surface <sdk-surface.json>',
      'hcp conformance readiness --conformance-scope <conformance-scope.json>',
      'hcp conformance readiness --protocol-requirements <protocol-requirements.json>',
      'hcp conformance readiness --transport-conformance <transport-conformance.json>',
      'hcp conformance readiness --wire-conformance <wire-conformance.json>',
      'hcp conformance readiness --manifest-conformance <manifest-conformance.json>',
      'hcp release plan [release-plan.json]',
      'hcp release alpha-gate [release-plan.json]',
      'hcp conformance registry --local <registry-dir> <manifest.json> <json-checks>'
    ]
  };
}

function usage() {
  console.log(`HCP prototype CLI

Usage:
  hcp dev [workspace]
  hcp stdio [workspace]
  hcp http [workspace] [port]
  hcp mcp stdio [workspace] [principal]
  hcp mcp proxy [--config .hcp/policy.json] [--server id] [--transport stdio|http] [--port port] [--max-inline-bytes bytes] [--approval-mode explicit|prompt|auto] [-- <command> <args...>]
  hcp mcp expose-runtime stdio [workspace] [principal]
  hcp mcp expose-runtime http [workspace] [port] [principal]
  hcp mcp wrap-server <stdio|http> <provider-id> <json-checks> <command-or-origin> [args-or-path]
  hcp mcp wrap-stdio <provider-id> <json-checks> <command> [args...]
  hcp mcp wrap-http <provider-id> <json-checks> <origin> [path]
  hcp mcp import-config <mcp-config.json> [--target cursor|claude|codex]
  hcp mcp config import <mcp-config.json> [--target cursor|claude|codex]
  hcp mcp config export <hcp-config.json> [--target cursor|claude|codex]
  hcp mcp doctor <mcp-or-hcp-config.json> [--format markdown|json] [--out report.md] [--workspace path]
  hcp mcp config doctor <mcp-or-hcp-config.json>
  hcp mcp config discover [workspace]
  hcp mcp config write <mcp-or-hcp-config.json> --target cursor|claude|codex [--scope user|workspace] [--path file] [--protect] [--dry-run|--yes]
  hcp mcp config protect [mcp-config.json] --target cursor|claude|codex [--scope user|workspace] [--path file] [--approval-mode explicit|prompt|auto] [--dry-run|--yes]
  hcp mcp config restore --target cursor|claude|codex [--scope user|workspace] [--path file] [--dry-run|--yes]
  hcp mcp config backup <config-path>
  hcp mcp config secretize <mcp-config.json> [workspace]
  hcp mcp risk-scan <json-server-or-config-file>
  hcp mcp inspect-command <command> [args...]
  hcp call <json-rpc-method> [json-params] [workspace]
  hcp cap search <query> [json-constraints] [workspace]
  hcp cap describe <capability-id> [workspace]
  hcp run <capability-id> <json-input> <json-options> [workspace]
  hcp task start <capability-id> <json-input> [workspace]
  hcp task run <capability-id> <json-input> <json-options> [workspace]
  hcp task watch <capability-id> <json-input> <json-options> [workspace]
  hcp trace <capability-id> <json-input> <json-options> [workspace]
  hcp trace run <capability-id> <json-input> <json-options> [workspace]
  hcp resource resolve <capability-id> <json-input> [json-options] [workspace]
  hcp data peek <source-capability-id> <json-source-input> <json-options> [workspace]
  hcp data pipe <source-capability-id> <json-source-input> <target-capability-id> <json-mapping> <json-options> [workspace]
  hcp data pipe --dry-run <source-capability-id> <json-source-input> <target-capability-id> <json-mapping> <json-options> [workspace]
  hcp audit trace <capability-id> <json-input> <json-options> [workspace]
  hcp audit explain <capability-id> <json-input> <json-options> [workspace]
  hcp audit report <capability-id> <json-input> <json-options> <out-file> [workspace]
  hcp audit search [json-filter] [workspace] [--file .hcp/audit.jsonl]
  hcp audit export [json-filter] [workspace] [--file .hcp/audit.jsonl]
  hcp audit tail [--file .hcp/audit.jsonl] [--limit 50] [workspace]
  hcp approval summary <capability-id> <json-input> <json-options> [workspace]
  hcp inspect [workspace]
  hcp inspect runtime [workspace]
  hcp inspect provider [provider-id] [workspace]
  hcp provider health <provider-id> [workspace]
  hcp provider register <manifest-file> [workspace]
  hcp provider verify <provider-id> [workspace]
  hcp provider reload <provider-id> [workspace]
  hcp provider quarantine <provider-id> [reason] [workspace]
  hcp policy explain <capability-id> <json-input> [json-options] [workspace]
  hcp policy decide <json-request> [workspace]
  hcp manifest validate <manifest-file>
  hcp registry validate <manifest-file>
  hcp registry publish --local <manifest-file> <registry-root>
  hcp registry install <manifest-file> <registry-root>
  hcp registry list <registry-root>
  hcp registry get <provider-id> <registry-root>
  hcp registry discover [json-filter] <registry-root>
  hcp registry verify <provider-id> <registry-root>
  hcp conformance <runtime|provider|client|registry|mcp-adapter|readiness> [...]
  hcp conformance runtime --stdio-check <json-checks> <command> [args...]
  hcp conformance runtime --http-check <json-checks> <origin>
  hcp conformance provider --stdio-behavior <json-checks> <command> [args...]
  hcp conformance provider --http-behavior <json-checks> <origin>
  hcp conformance client --stdio-check <json-checks> <command> [args...]
  hcp conformance client --http-check <json-checks> <origin>
  hcp conformance readiness --provider-lifecycle <provider-lifecycle.json>
  hcp conformance readiness --sdk-surface <sdk-surface.json>
  hcp conformance readiness --conformance-scope <conformance-scope.json>
  hcp conformance readiness --protocol-requirements <protocol-requirements.json>
  hcp conformance readiness --transport-conformance <transport-conformance.json>
  hcp conformance readiness --wire-conformance <wire-conformance.json>
  hcp conformance readiness --manifest-conformance <manifest-conformance.json>
  hcp release plan [release-plan.json]
  hcp release alpha-gate [release-plan.json]
  hcp demo [workspace]

Examples:
  hcp dev .
  hcp call cap.search '{"query":"read markdown","constraints":{"limit":3}}' .
  hcp call cap.describe '{"capability_id":"filesystem.file.read","detail_level":"summary"}' .
  hcp cap search "read markdown" '{"tool_budget":3}' .
  hcp mcp import-config ./mcp.json --target cursor
  hcp mcp doctor ./mcp.json --format markdown --out ./hcp-mcp-governance-report.md
  hcp mcp config doctor ./mcp.json
  hcp mcp config discover .
  hcp mcp config write ./hcp-mcp.json --target cursor --scope workspace --dry-run
  hcp mcp config secretize ./mcp.json .
  hcp mcp risk-scan '{"command":"npx","args":["-y","@example/mcp-server"],"env":{"API_TOKEN":"redacted"}}'
  hcp approval summary filesystem.file.write '{"path":"out.md","content":"hello"}' '{"principal":"user:alex"}' .
  hcp task start filesystem.file.list '{"path":".","max_depth":1}' .
  hcp run filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' .
  hcp task run filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' .
  hcp task watch filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true,"since_event":0}' .
  hcp trace filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' .
  hcp trace run filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' .
  hcp audit trace filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' .
  hcp audit explain filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' .
  hcp audit report filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true}' ./audit-report.json .
  hcp audit search '{"type":"POLICY_DECISION"}' .
  hcp data peek filesystem.file.read '{"path":"doc.md"}' '{"principal":"user:alex","grant":true,"mode":"preview"}' .
  hcp data pipe filesystem.file.read '{"path":"doc.md"}' filesystem.file.write '{"target_field":"content","input":{"path":"copy.md"}}' '{"principal":"user:alex","grant":true,"approval":{"approved":true}}' .
  hcp data pipe --dry-run filesystem.file.read '{"path":"doc.md"}' filesystem.file.write '{"target_field":"content","input":{"path":"copy.md"}}' '{"principal":"user:alex","grant":true}' .
  hcp inspect .
  hcp manifest validate ../docs/examples/local-filesystem-provider.manifest.json
  hcp registry publish --local ../docs/examples/local-filesystem-provider.manifest.json ./.hcp-registry
  hcp conformance runtime --self-test
  hcp conformance runtime --stdio-check '{"resourceResolve":{"capability":"filesystem.file.read","input":{"path":"./doc.md"},"expectedResource":"file:doc.md"}}' node hcp-runtime/src/cli.js stdio .
  hcp conformance provider --stdio-behavior '{"capability":"example.echo","scope":"example:echo","resource":"example:hello","input":{"text":"hello"}}' node ./provider.js
  hcp conformance client --stdio-check '{"readInput":{"path":"doc.md"},"readResource":"file:doc.md"}' node hcp-runtime/src/cli.js stdio .
  hcp mcp expose-runtime stdio . user:alex
  hcp mcp expose-runtime http . 0 user:alex
  hcp mcp wrap-server stdio mcp.local '{"capability":"mcp.local.echo","input":{"text":"hello"},"resource":"mcp:echo","scopes":["mcp:echo:call"]}' node ./my-mcp-server.js
  hcp mcp wrap-server http mcp.http '{"capability":"mcp.http.echo","input":{"text":"hello"},"resource":"mcp:echo","scopes":["mcp:echo:call"]}' http://127.0.0.1:8788 /mcp
  hcp mcp wrap-stdio mcp.local '{"capability":"mcp.local.echo","input":{"text":"hello"},"resource":"mcp:echo","scopes":["mcp:echo:call"]}' node ./my-mcp-server.js
  hcp mcp wrap-http mcp.http '{"capability":"mcp.http.echo","input":{"text":"hello"},"resource":"mcp:echo","scopes":["mcp:echo:call"]}' http://127.0.0.1:8788 /mcp
  hcp conformance readiness --self-test
  hcp release plan docs/release-plan.json
  hcp release alpha-gate docs/release-plan.json
  hcp conformance registry --local ./.hcp-registry docs/examples/local-filesystem-provider.manifest.json '{"providerId":"local.filesystem","capabilityId":"filesystem.file.read","scope":"filesystem:read","effect":"read","risk":"low","maxRisk":"medium","expectedDiscoveryCount":2,"transport":"stdio"}'
`);
}

async function main(argv) {
  const [area, command, ...rest] = argv.slice(2);

  if (!area || area === '--help' || area === '-h') {
    usage();
    return;
  }

  if (area === 'demo') {
    const workspace = command ?? cwd();
    const runtime = await makeRuntime(workspace);
    const search = await runtime.capSearch('list files read markdown', { limit: 3 });
    print({ workspace, search });
    return;
  }

  if (area === 'dev') {
    const workspace = command ?? cwd();
    print(await inspectDevWorkspace(workspace));
    return;
  }

  if (area === 'stdio') {
    const workspace = command ?? cwd();
    const runtime = await makeRuntime(workspace);
    await serveJsonRpcStdio({ runtime });
    return;
  }

  if (area === 'mcp' && command === 'stdio') {
    const workspace = rest[0] ?? cwd();
    const principal = rest[1] ?? null;
    const runtime = await makeRuntime(workspace);
    await serveMcpStdio({ runtime, mcp: { principal } });
    return;
  }

  if (area === 'mcp' && command === 'proxy') {
    const dashIndex = rest.indexOf('--');
    const optionArgs = dashIndex === -1 ? rest : rest.slice(0, dashIndex);
    const passthroughArgs = dashIndex === -1 ? [] : rest.slice(dashIndex + 1);

    const workspace = optionValue(optionArgs, '--workspace', cwd());
    const configPath = optionValue(optionArgs, '--config', null);
    const serverId = optionValue(optionArgs, '--server', null);
    const transport = optionValue(optionArgs, '--transport', 'stdio');
    const host = optionValue(optionArgs, '--host', '127.0.0.1');
    const port = Number.parseInt(optionValue(optionArgs, '--port', '0'), 10);
    const principal = optionValue(optionArgs, '--principal', null);
    const auditLogPath = hasFlag(optionArgs, '--no-audit-log')
      ? false
      : optionValue(optionArgs, '--audit-log', undefined);
    const secretsPath = optionValue(optionArgs, '--secrets', null);
    const maxInlineBytesRaw = optionValue(optionArgs, '--max-inline-bytes', null);
    const maxInlineBytes = maxInlineBytesRaw !== null
      ? Number.parseInt(maxInlineBytesRaw, 10)
      : undefined;
    const interceptSecrets = hasFlag(optionArgs, '--no-secret-intercept')
      ? false
      : hasFlag(optionArgs, '--intercept-secrets')
        ? true
        : undefined;
    const offloadLargeOutputs = hasFlag(optionArgs, '--no-large-offload')
      ? false
      : hasFlag(optionArgs, '--offload-large-outputs')
        ? true
        : undefined;
    const exposeVaultTools = hasFlag(optionArgs, '--no-vault-tools')
      ? false
      : undefined;
    const origin = optionValue(optionArgs, '--origin', null);
    const approvalMode = optionValue(optionArgs, '--approval-mode', undefined);

    let policyInput = configPath;
    if (!policyInput) {
      const defaultPolicyFile = join(workspace, '.hcp', 'policy.json');
      if (passthroughArgs.length > 0) {
        const [upstreamCommand, ...upstreamArgs] = passthroughArgs;
        const inlineId = serverId ?? 'upstream';
        policyInput = createDefaultMcpProxyPolicy({
          servers: {
            [inlineId]: {
              id: inlineId,
              provider_id: `mcp.${inlineId}`,
              transport: 'stdio',
              command: upstreamCommand,
              args: upstreamArgs
            }
          }
        });
      } else if (origin) {
        const inlineId = serverId ?? 'upstream';
        policyInput = createDefaultMcpProxyPolicy({
          servers: {
            [inlineId]: {
              id: inlineId,
              provider_id: `mcp.${inlineId}`,
              transport: 'http',
              origin
            }
          }
        });
      } else if (existsSync(defaultPolicyFile)) {
        policyInput = defaultPolicyFile;
      } else {
        throw new Error('hcp mcp proxy requires --config <.hcp/policy.json>, --origin <url>, or -- <command> [args...]');
      }
    }

    const proxy = await serveMcpProxy({
      policy: policyInput,
      workspace,
      serverId,
      principal,
      auditLogPath,
      secretsPath,
      maxInlineBytes,
      interceptSecrets,
      offloadLargeOutputs,
      exposeVaultTools,
      approvalMode,
      transport,
      host,
      port: Number.isNaN(port) ? 0 : port
    });
    for (const item of proxy.policy.unresolved_secrets ?? []) {
      console.error(`[hcp] warning: unresolved secret reference ${item.key} for server ${item.server}; not forwarded to upstream`);
    }
    if (transport === 'http') {
      console.error(`HCP MCP Proxy HTTP listening on ${proxy.origin} (approval_mode=${proxy.approvalMode})`);
    }
    return;
  }

  if (area === 'mcp' && (command === 'protect' || command === 'restore')) {
    rest.unshift(command);
    return main([argv[0], argv[1], 'mcp', 'config', ...rest]);
  }

  if (area === 'mcp' && command === 'import-config') {
    const configFile = rest[0];
    if (!configFile) throw new Error('hcp mcp import-config requires <mcp-config.json>');
    const target = parseTargetOption(rest.slice(1), 'generic');
    const config = await parseJsonOrFile(configFile);
    print(importMcpConfig(config, { source: configFile, target }));
    return;
  }

  if (area === 'mcp' && command === 'doctor') {
    const configFile = rest[0];
    if (!configFile) throw new Error('hcp mcp doctor requires <mcp-or-hcp-config.json>');
    const options = rest.slice(1);
    const format = hasFlag(options, '--json')
      ? 'json'
      : hasFlag(options, '--markdown')
        ? 'markdown'
        : optionValue(options, '--format', 'markdown');
    if (!['json', 'markdown'].includes(format)) {
      throw new Error('hcp mcp doctor --format must be json or markdown');
    }
    const workspace = optionValue(options, '--workspace', cwd());
    const outFile = optionValue(options, '--out', null);
    const report = await buildMcpDoctorReport(configFile, { workspace });
    const rendered = format === 'json'
      ? `${JSON.stringify(report, null, 2)}\n`
      : renderMcpDoctorMarkdown(report);

    if (outFile) {
      const written = await writeTextFile(outFile, rendered.endsWith('\n') ? rendered : `${rendered}\n`);
      print({
        kind: 'hcp.mcp.doctor_report_written',
        format,
        path: written.path,
        bytes: written.bytes,
        summary: report.summary
      });
      return;
    }

    if (format === 'json') {
      print(report);
    } else {
      console.log(rendered);
    }
    return;
  }

  if (area === 'mcp' && command === 'config') {
    const subcommand = rest[0];
    const configFile = rest[1];
    if (subcommand === 'import') {
      if (!configFile) throw new Error('hcp mcp config import requires <mcp-config.json>');
      const target = parseTargetOption(rest.slice(2), 'generic');
      const config = await parseJsonOrFile(configFile);
      print(importMcpConfig(config, { source: configFile, target }));
      return;
    }
    if (subcommand === 'export') {
      if (!configFile) throw new Error('hcp mcp config export requires <hcp-config.json>');
      const target = parseTargetOption(rest.slice(2), 'generic');
      const config = await parseJsonOrFile(configFile);
      print(exportMcpConfig(config, { target }));
      return;
    }
    if (subcommand === 'doctor') {
      if (!configFile) throw new Error('hcp mcp config doctor requires <mcp-or-hcp-config.json>');
      const config = await parseJsonOrFile(configFile);
      print(doctorMcpConfig(config, { source: configFile }));
      return;
    }
    if (subcommand === 'discover') {
      const workspace = configFile ?? cwd();
      print(await inspectMcpConfigTargets({ workspace }));
      return;
    }
    if (subcommand === 'backup') {
      if (!configFile) throw new Error('hcp mcp config backup requires <config-path>');
      print(await backupMcpConfig(configFile));
      return;
    }
    if (subcommand === 'secretize') {
      if (!configFile) throw new Error('hcp mcp config secretize requires <mcp-config.json>');
      const workspace = rest[2] ?? cwd();
      const config = await parseJsonOrFile(configFile);
      print(await secretizeMcpConfig(config, { workspace }));
      return;
    }
    if (subcommand === 'write') {
      if (!configFile) throw new Error('hcp mcp config write requires <mcp-or-hcp-config.json>');
      const options = rest.slice(2);
      const target = optionValue(options, '--target', 'generic');
      const scope = optionValue(options, '--scope', null);
      const configPath = optionValue(options, '--path', null);
      const workspace = optionValue(options, '--workspace', cwd());
      const protect = hasFlag(options, '--protect');
      const policyPath = optionValue(options, '--policy', null);
      const vaultPath = optionValue(options, '--vault', null);
      const proxyCommand = optionValue(options, '--proxy-command', undefined);
      const proxyArgsPrefixRaw = optionValue(options, '--proxy-args', null);
      const proxyArgsPrefix = proxyArgsPrefixRaw !== null ? JSON.parse(proxyArgsPrefixRaw) : undefined;
      const config = await parseJsonOrFile(configFile);
      print(await writeMcpClientConfig(config, {
        target,
        scope,
        configPath,
        workspace,
        protect,
        policyPath,
        vaultPath,
        ...(proxyCommand !== undefined ? { proxyCommand } : {}),
        ...(proxyArgsPrefix !== undefined ? { proxyArgsPrefix } : {}),
        dryRun: hasFlag(options, '--dry-run'),
        yes: hasFlag(options, '--yes')
      }));
      return;
    }
    if (subcommand === 'protect') {
      const hasConfigArg = configFile && !configFile.startsWith('--');
      const options = hasConfigArg ? rest.slice(2) : rest.slice(1);
      const target = optionValue(options, '--target', 'cursor');
      const scope = optionValue(options, '--scope', null);
      const configPath = optionValue(options, '--path', null);
      const workspace = optionValue(options, '--workspace', cwd());
      const policyPath = optionValue(options, '--policy', null);
      const vaultPath = optionValue(options, '--vault', null);
      const auditLogPath = optionValue(options, '--audit-log', null);
      const approvalMode = optionValue(options, '--approval-mode', undefined);
      const proxyCommand = optionValue(options, '--proxy-command', undefined);
      const proxyArgsPrefixRaw = optionValue(options, '--proxy-args', null);
      const proxyArgsPrefix = proxyArgsPrefixRaw !== null ? JSON.parse(proxyArgsPrefixRaw) : undefined;
      const config = hasConfigArg ? await parseJsonOrFile(configFile) : null;
      print(await protectMcpClientConfig(config, {
        target,
        scope,
        configPath,
        workspace,
        policyPath,
        vaultPath,
        auditLogPath,
        ...(approvalMode !== undefined ? { approvalMode } : {}),
        ...(proxyCommand !== undefined ? { proxyCommand } : {}),
        ...(proxyArgsPrefix !== undefined ? { proxyArgsPrefix } : {}),
        dryRun: hasFlag(options, '--dry-run'),
        yes: hasFlag(options, '--yes')
      }));
      return;
    }
    if (subcommand === 'restore') {
      const options = rest.slice(1);
      const target = optionValue(options, '--target', 'cursor');
      const scope = optionValue(options, '--scope', null);
      const configPath = optionValue(options, '--path', null);
      const backupPath = optionValue(options, '--backup', null);
      const workspace = optionValue(options, '--workspace', cwd());
      print(await restoreMcpClientConfig({
        target,
        scope,
        configPath,
        backupPath,
        workspace,
        dryRun: hasFlag(options, '--dry-run'),
        yes: hasFlag(options, '--yes')
      }));
      return;
    }
    throw new Error('hcp mcp config requires import, export, doctor, discover, backup, secretize, write, protect, or restore');
  }

  if (area === 'mcp' && command === 'risk-scan') {
    const input = await parseJsonOrFile(rest[0], {});
    if (input.mcpServers || input.servers || input.kind === 'hcp.mcp.governance_config') {
      print(doctorMcpConfig(input));
    } else {
      print(scanMcpServerCommand(input));
    }
    return;
  }

  if (area === 'mcp' && command === 'inspect-command') {
    const mcpCommand = rest[0];
    if (!mcpCommand) throw new Error('hcp mcp inspect-command requires <command> [args...]');
    print(scanMcpServerCommand({ command: mcpCommand, args: rest.slice(1) }));
    return;
  }

  if (area === 'mcp' && command === 'expose-runtime') {
    const transport = rest[0];
    if (transport === 'stdio') {
      const workspace = rest[1] ?? cwd();
      const principal = rest[2] ?? null;
      const runtime = await makeRuntime(workspace);
      await serveMcpStdio({ runtime, mcp: { principal } });
      return;
    }
    if (transport === 'http') {
      const workspace = rest[1] ?? cwd();
      const port = Number.parseInt(rest[2] ?? '0', 10);
      const principal = rest[3] ?? null;
      const runtime = await makeRuntime(workspace);
      const server = await serveJsonRpcHttp({
        runtime,
        port: Number.isNaN(port) ? 0 : port,
        mcp: { principal }
      });
      console.error(`HCP MCP-like HTTP listening on ${server.origin}`);
      return;
    }
    throw new Error('hcp mcp expose-runtime requires transport stdio or http');
  }

  if (area === 'mcp' && command === 'wrap-stdio') {
    const providerId = rest[0];
    const checks = parseJson(rest[1], {});
    const mcpCommand = rest[2];
    const args = rest.slice(3);
    if (!providerId || !mcpCommand) {
      throw new Error('hcp mcp wrap-stdio requires <provider-id> <json-checks> <command> [args...]');
    }
    print(await runMcpWrapStdioSmoke({
      providerId,
      checks,
      command: mcpCommand,
      args,
      workspace: checks.workspace ?? cwd(),
      timeoutMs: checks.timeout_ms ?? 5000
    }));
    return;
  }

  if (area === 'mcp' && command === 'wrap-server') {
    const transport = rest[0];
    const providerId = rest[1];
    const checks = parseJson(rest[2], {});
    if (transport === 'stdio') {
      const mcpCommand = rest[3];
      const args = rest.slice(4);
      if (!providerId || !mcpCommand) {
        throw new Error('hcp mcp wrap-server stdio requires <provider-id> <json-checks> <command> [args...]');
      }
      print(await runMcpWrapStdioSmoke({
        providerId,
        checks,
        command: mcpCommand,
        args,
        workspace: checks.workspace ?? cwd(),
        timeoutMs: checks.timeout_ms ?? 5000
      }));
      return;
    }
    if (transport === 'http') {
      const origin = rest[3];
      const path = rest[4] ?? checks.path ?? '/mcp';
      if (!providerId || !origin) {
        throw new Error('hcp mcp wrap-server http requires <provider-id> <json-checks> <origin> [path]');
      }
      print(await runMcpWrapHttpSmoke({
        providerId,
        checks,
        origin,
        path,
        workspace: checks.workspace ?? cwd()
      }));
      return;
    }
    throw new Error('hcp mcp wrap-server requires transport stdio or http');
  }

  if (area === 'mcp' && command === 'wrap-http') {
    const providerId = rest[0];
    const checks = parseJson(rest[1], {});
    const origin = rest[2];
    const path = rest[3] ?? checks.path ?? '/mcp';
    if (!providerId || !origin) {
      throw new Error('hcp mcp wrap-http requires <provider-id> <json-checks> <origin> [path]');
    }
    print(await runMcpWrapHttpSmoke({
      providerId,
      checks,
      origin,
      path,
      workspace: checks.workspace ?? cwd()
    }));
    return;
  }

  if (area === 'http') {
    const workspace = command ?? cwd();
    const port = Number.parseInt(rest[0] ?? '0', 10);
    const runtime = await makeRuntime(workspace);
    const server = await serveJsonRpcHttp({ runtime, port: Number.isNaN(port) ? 0 : port });
    console.error(`HCP HTTP listening on ${server.origin}`);
    return;
  }

  if (area === 'conformance') {
    if (!existsSync(CONFORMANCE_CLI)) {
      throw new Error('hcp conformance requires a full repository checkout (packages/hcp-conformance)');
    }
    const exitCode = await runPassthroughNode(CONFORMANCE_CLI, [command, ...rest].filter(Boolean));
    if (exitCode !== 0) process.exitCode = exitCode;
    return;
  }

  if (area === 'release') {
    if (!existsSync(CONFORMANCE_CLI)) {
      throw new Error('hcp release requires a full repository checkout (packages/hcp-conformance)');
    }
    const releasePlanPath = rest[0] ?? 'docs/release-plan.json';
    if (command === 'plan') {
      const exitCode = await runPassthroughNode(CONFORMANCE_CLI, ['readiness', '--release-plan', releasePlanPath]);
      if (exitCode !== 0) process.exitCode = exitCode;
      return;
    }
    if (command === 'alpha-gate') {
      const exitCode = await runPassthroughNode(CONFORMANCE_CLI, ['readiness', '--alpha-gate', releasePlanPath]);
      if (exitCode !== 0) process.exitCode = exitCode;
      return;
    }
    throw new Error('hcp release requires plan or alpha-gate');
  }

  if (area === 'call') {
    const method = command;
    const { params, workspace } = parseCallArgs(rest);
    const runtime = await makeRuntime(workspace);
    const client = new HcpJsonRpcClient({
      transport: createInMemoryJsonRpcTransport(createHcpJsonRpcDispatcher(runtime))
    });
    print(await client.request(method, params));
    return;
  }

  if (area === 'cap' && command === 'search') {
    const query = rest[0] ?? '';
    const hasConstraints = rest[1] && /^[\s]*\{/.test(rest[1]);
    const constraints = hasConstraints ? parseJson(rest[1], {}) : { limit: 7 };
    const workspace = hasConstraints ? rest[2] ?? cwd() : rest[1] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.capSearch(query, constraints));
    return;
  }

  if (area === 'cap' && command === 'describe') {
    const capabilityId = rest[0];
    const workspace = rest[1] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(runtime.capDescribe(capabilityId, 'full'));
    return;
  }

  if (area === 'task' && command === 'start') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const workspace = rest[2] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.taskStart(capabilityId, input, { approval: { approved: true } }));
    return;
  }

  if (area === 'task' && command === 'run') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    print(await runLocalTask({ capabilityId, input, options, workspace, resolveResult: true }));
    return;
  }

  if (area === 'task' && command === 'watch') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    const runtime = await makeRuntime(workspace);
    const taskOptions = { ...options };
    const grantOption = taskOptions.grant;
    const sinceEvent = Number.parseInt(taskOptions.since_event ?? '0', 10);
    const waitMs = Number.parseInt(taskOptions.wait_ms ?? '0', 10);
    delete taskOptions.grant;
    delete taskOptions.since_event;
    delete taskOptions.wait_ms;

    const grant = await createLocalGrantForCapability(runtime, capabilityId, input, taskOptions, grantOption);
    const task = await runtime.taskStart(capabilityId, input, taskOptions);
    const events = await runtime.taskWatchWait(
      task.task_id,
      Number.isNaN(sinceEvent) ? 0 : sinceEvent,
      { wait_ms: Number.isNaN(waitMs) ? 0 : waitMs }
    );

    print({
      grant,
      task,
      since_event: Number.isNaN(sinceEvent) ? 0 : sinceEvent,
      events,
      trace: task.task_id ? runtime.auditGetTrace(task.task_id) : null
    });
    return;
  }

  if (area === 'run') {
    const capabilityId = command;
    const input = parseJson(rest[0], {});
    const options = parseJson(rest[1], {});
    const workspace = rest[2] ?? cwd();
    print(await runLocalTask({ capabilityId, input, options, workspace, resolveResult: true }));
    return;
  }

  if (area === 'trace' && command === 'run') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    print(await runLocalTask({ capabilityId, input, options, workspace, resolveResult: false }));
    return;
  }

  if (area === 'trace') {
    const capabilityId = command;
    const input = parseJson(rest[0], {});
    const options = parseJson(rest[1], {});
    const workspace = rest[2] ?? cwd();
    print(await runLocalTask({ capabilityId, input, options, workspace, resolveResult: false }));
    return;
  }

  if (area === 'data' && command === 'pipe') {
    const dryRun = rest[0] === '--dry-run';
    const args = dryRun ? rest.slice(1) : rest;
    const sourceCapabilityId = args[0];
    const sourceInput = parseJson(args[1], {});
    const targetCapabilityId = args[2];
    const mapping = parseJson(args[3], {});
    const options = parseJson(args[4], {});
    if (dryRun) options.dry_run = true;
    const workspace = args[5] ?? cwd();
    const runtime = await makeRuntime(workspace);
    const pipeOptions = { ...options };
    const grantOption = pipeOptions.grant;
    delete pipeOptions.grant;

    const sourceGrant = await createLocalGrantForCapability(
      runtime,
      sourceCapabilityId,
      sourceInput,
      pipeOptions,
      grantOption?.source ?? grantOption
    );
    const sourceTask = await runtime.taskStart(sourceCapabilityId, sourceInput, pipeOptions);
    if (sourceTask.status !== 'COMPLETED' || !sourceTask.result?.handle) {
      print({
        source_grant: sourceGrant,
        source_task: sourceTask,
        pipe_task: null,
        source_trace: sourceTask.task_id ? runtime.auditGetTrace(sourceTask.task_id) : null,
        target_trace: null
      });
      return;
    }

    const targetInput = {
      ...(mapping.input ?? {}),
      [mapping.target_field ?? 'body']: ''
    };
    const targetGrant = await createLocalGrantForCapability(
      runtime,
      targetCapabilityId,
      targetInput,
      pipeOptions,
      grantOption?.target ?? grantOption
    );
    const pipeTask = await runtime.dataPipe(sourceTask.result.handle, targetCapabilityId, mapping, pipeOptions);

    print({
      dry_run: dryRun || pipeOptions.dry_run === true,
      source_grant: sourceGrant,
      target_grant: targetGrant,
      source_task: sourceTask,
      pipe_task: pipeTask,
      source_trace: runtime.auditGetTrace(sourceTask.task_id),
      target_trace: pipeTask.task_id ? runtime.auditGetTrace(pipeTask.task_id) : null
    });
    return;
  }

  if (area === 'data' && command === 'peek') {
    const sourceCapabilityId = rest[0];
    const sourceInput = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    const runtime = await makeRuntime(workspace);
    const taskOptions = { ...options };
    const grantOption = taskOptions.grant;
    const projection = {
      ...(taskOptions.projection ?? {}),
      mode: taskOptions.projection?.mode ?? taskOptions.mode ?? 'preview'
    };
    delete taskOptions.grant;
    delete taskOptions.mode;
    delete taskOptions.projection;

    const sourceGrant = await createLocalGrantForCapability(
      runtime,
      sourceCapabilityId,
      sourceInput,
      taskOptions,
      grantOption
    );
    const sourceTask = await runtime.taskStart(sourceCapabilityId, sourceInput, taskOptions);
    let peek = null;
    if (sourceTask.status === 'COMPLETED' && sourceTask.result?.handle) {
      peek = runtime.dataPeek(sourceTask.result.handle, projection, { principal: taskOptions.principal });
    }

    print({
      source_grant: sourceGrant,
      source_task: sourceTask,
      projection,
      peek,
      source_trace: sourceTask.task_id ? runtime.auditGetTrace(sourceTask.task_id) : null
    });
    return;
  }

  if (area === 'audit' && command === 'search') {
    const fileOpt = optionValue(rest, '--file', null);
    const positional = rest.filter((arg, idx) => arg !== '--file' && (idx === 0 || rest[idx - 1] !== '--file'));
    const filter = positional[0] && /^[\s]*\{/.test(positional[0]) ? parseJson(positional[0], {}) : {};
    const workspace = (positional[0] && /^[\s]*\{/.test(positional[0]) ? positional[1] : positional[0]) ?? cwd();
    if (fileOpt) {
      const resolvedFile = resolve(workspace, fileOpt);
      const entries = readAuditLogEntries(resolvedFile).filter((entry) => matchesAuditFilter(entry, filter));
      print(entries);
      return;
    }
    const runtime = await makeRuntime(workspace);
    print(runtime.auditSearch(filter));
    return;
  }

  if (area === 'audit' && command === 'tail') {
    const fileOpt = optionValue(rest, '--file', null);
    const limitRaw = optionValue(rest, '--limit', '50');
    const limit = Number.parseInt(limitRaw, 10);
    const positional = rest.filter((arg, idx) => (
      arg !== '--file' &&
      arg !== '--limit' &&
      (idx === 0 || (rest[idx - 1] !== '--file' && rest[idx - 1] !== '--limit'))
    ));
    const workspace = positional[0] ?? cwd();
    const auditFile = fileOpt ? resolve(workspace, fileOpt) : join(workspace, '.hcp', 'audit.jsonl');
    const entries = tailAuditLogEntries(auditFile, { limit: Number.isNaN(limit) ? 50 : limit });
    print({
      kind: 'hcp.audit.tail',
      path: auditFile,
      count: entries.length,
      entries
    });
    return;
  }

  if (area === 'audit' && command === 'trace') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    print(await runLocalTask({ capabilityId, input, options, workspace, resolveResult: false }));
    return;
  }

  if (area === 'audit' && command === 'explain') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    const output = await runLocalTask({ capabilityId, input, options, workspace, resolveResult: false });
    print({
      ...output,
      explanation: output.trace ? explainAuditTrace(output.trace) : null
    });
    return;
  }

  if (area === 'audit' && command === 'report') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const outFile = rest[3];
    const workspace = rest[4] ?? cwd();
    if (!outFile) throw new Error('hcp audit report requires <out-file>');
    const output = await runLocalTask({ capabilityId, input, options, workspace, resolveResult: false });
    const report = {
      kind: 'hcp.audit.explain_report',
      generated_at: new Date().toISOString(),
      workspace,
      run: output,
      explanation: output.trace ? explainAuditTrace(output.trace) : null
    };
    const written = await writeJsonFile(outFile, report);
    print({
      ...written,
      kind: report.kind,
      task_id: output.task?.task_id ?? null,
      status: output.task?.status ?? null,
      audit_entry_count: report.explanation?.audit_entry_count ?? 0
    });
    return;
  }

  if (area === 'audit' && command === 'export') {
    const fileOpt = optionValue(rest, '--file', null);
    const positional = rest.filter((arg, idx) => arg !== '--file' && (idx === 0 || rest[idx - 1] !== '--file'));
    const filter = positional[0] && /^[\s]*\{/.test(positional[0]) ? parseJson(positional[0], {}) : {};
    const workspace = (positional[0] && /^[\s]*\{/.test(positional[0]) ? positional[1] : positional[0]) ?? cwd();
    if (fileOpt) {
      const resolvedFile = resolve(workspace, fileOpt);
      const entries = readAuditLogEntries(resolvedFile).filter((entry) => matchesAuditFilter(entry, filter));
      print({
        exported_at: new Date().toISOString(),
        path: resolvedFile,
        count: entries.length,
        entries
      });
      return;
    }
    const runtime = await makeRuntime(workspace);
    print(runtime.auditExport(filter));
    return;
  }

  if (area === 'approval' && command === 'summary') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    const runtime = await makeRuntime(workspace);
    const summaryOptions = { ...options };
    const grantOption = summaryOptions.grant;
    delete summaryOptions.grant;
    const grant = await createLocalGrantForCapability(runtime, capabilityId, input, summaryOptions, grantOption);
    const explanation = await runtime.policyExplain(capabilityId, input, summaryOptions);
    const capability = runtime.capDescribe(capabilityId, 'full');
    print({
      grant,
      explanation,
      summary: buildApprovalSummary(explanation, capability)
    });
    return;
  }

  if (area === 'resource' && command === 'resolve') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.resourceResolve(capabilityId, input, options));
    return;
  }

  if (area === 'inspect' && command === 'runtime') {
    const workspace = rest[0] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.inspectRuntime());
    return;
  }

  if (area === 'inspect' && (!command || command.startsWith('.') || command.includes(':') || command.includes('\\') || command.includes('/'))) {
    const workspace = command ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.inspectRuntime());
    return;
  }

  if (area === 'inspect' && command === 'provider') {
    const providerId = rest[0] && !rest[0].startsWith('.') ? rest[0] : null;
    const workspace = providerId ? rest[1] ?? cwd() : rest[0] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.inspectProvider(providerId));
    return;
  }

  if (area === 'provider' && command === 'health') {
    const providerId = rest[0];
    const workspace = rest[1] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.providerHealth(providerId));
    return;
  }

  if (area === 'provider' && command === 'register') {
    const manifestFile = rest[0];
    const workspace = rest[1] ?? cwd();
    const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
    const runtime = await makeRuntime(workspace);
    print(runtime.providerRegister(manifest, { source: manifestFile }));
    return;
  }

  if (area === 'provider' && command === 'verify') {
    const providerId = rest[0];
    const workspace = rest[1] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(runtime.providerVerify(providerId));
    return;
  }

  if (area === 'provider' && command === 'reload') {
    const providerId = rest[0];
    const workspace = rest[1] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.providerReload(providerId));
    return;
  }

  if (area === 'provider' && command === 'quarantine') {
    const providerId = rest[0];
    const reason = rest[1] ?? 'quarantined';
    const workspace = rest[2] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(runtime.providerQuarantine(providerId, reason));
    return;
  }

  if (area === 'policy' && command === 'explain') {
    const capabilityId = rest[0];
    const input = parseJson(rest[1], {});
    const options = parseJson(rest[2], {});
    const workspace = rest[3] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.policyExplain(capabilityId, input, options));
    return;
  }

  if (area === 'policy' && command === 'decide') {
    const request = parseJson(rest[0], {});
    const workspace = rest[1] ?? cwd();
    const runtime = await makeRuntime(workspace);
    print(await runtime.policyExplain(request.capability_id, request.input ?? {}, request.options ?? {}, {
      operation: request.operation ?? 'invoke'
    }));
    return;
  }

  if (area === 'manifest' && command === 'validate') {
    const manifestFile = rest[0];
    const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
    print(validateRegistryManifest(manifest));
    return;
  }

  if (area === 'registry' && command === 'validate') {
    const manifestFile = rest[0];
    const registry = createLocalManifestRegistry({ root: cwd() });
    print(await registry.validateManifestFile(manifestFile));
    return;
  }

  if (area === 'registry' && command === 'install') {
    const manifestFile = rest[0];
    const registryRoot = rest[1] ?? '.hcp-registry';
    const registry = createLocalManifestRegistry({ root: registryRoot });
    print(await registry.installManifestFile(manifestFile));
    return;
  }

  if (area === 'registry' && command === 'publish') {
    const mode = rest[0];
    if (mode !== '--local') {
      throw new Error('hcp registry publish currently supports only --local');
    }
    const manifestFile = rest[1];
    const registryRoot = rest[2] ?? '.hcp-registry';
    const registry = createLocalManifestRegistry({ root: registryRoot });
    print(await registry.publishLocalManifestFile(manifestFile));
    return;
  }

  if (area === 'registry' && command === 'list') {
    const registryRoot = rest[0] ?? '.hcp-registry';
    const registry = createLocalManifestRegistry({ root: registryRoot });
    print(await registry.list());
    return;
  }

  if (area === 'registry' && command === 'get') {
    const providerId = rest[0];
    const registryRoot = rest[1] ?? '.hcp-registry';
    const registry = createLocalManifestRegistry({ root: registryRoot });
    print(await registry.get(providerId));
    return;
  }

  if (area === 'registry' && command === 'discover') {
    const filter = parseJson(rest[0], {});
    const registryRoot = rest[1] ?? '.hcp-registry';
    const registry = createLocalManifestRegistry({ root: registryRoot });
    print(await registry.discover(filter));
    return;
  }

  if (area === 'registry' && command === 'verify') {
    const providerId = rest[0];
    const registryRoot = rest[1] ?? '.hcp-registry';
    const registry = createLocalManifestRegistry({ root: registryRoot });
    print(await registry.verify(providerId));
    return;
  }

  usage();
}

main(process.argv).catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
