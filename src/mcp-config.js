import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createDefaultMcpProxyPolicy } from './mcp/proxy.js';
import { HCP_RUNTIME_PACKAGE_SPEC } from './package-info.js';

const SECRET_ENV_KEY_PATTERN = /(TOKEN|SECRET|PASSWORD|PASS|API[_-]?KEY|AUTH|BEARER|COOKIE|CREDENTIAL|PRIVATE)/i;
const PACKAGE_RUNNERS = new Set(['npx', 'uvx', 'bunx']);
const SHELL_COMMANDS = new Set(['cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe', 'bash', 'sh']);
const MCP_CONFIG_SCOPES = new Set(['user', 'workspace']);
const HCP_TOML_BLOCK_START = '# BEGIN HCP-MANAGED MCP SERVERS';
const HCP_TOML_BLOCK_END = '# END HCP-MANAGED MCP SERVERS';

function commandBase(command = '') {
  return String(command).split(/[\\/]/).pop().toLowerCase();
}

function normalizeArgs(args = []) {
  if (Array.isArray(args)) return args.map(String);
  if (typeof args === 'string' && args.length > 0) return [args];
  return [];
}

function normalizeEnv(env = {}) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return {};
  return Object.fromEntries(Object.keys(env).sort().map((key) => [key, String(env[key] ?? '')]));
}

function redactUrl(value) {
  if (!value) return value;
  try {
    const parsed = new URL(String(value));
    if (parsed.username) parsed.username = 'redacted';
    if (parsed.password) parsed.password = 'redacted';
    for (const key of [...parsed.searchParams.keys()]) {
      if (isSensitiveEnvKey(key)) {
        parsed.searchParams.set(key, 'redacted');
      }
    }
    if (parsed.hash) parsed.hash = '#redacted';
    return parsed.toString();
  } catch {
    return String(value);
  }
}

function timestampForFile(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

async function fileExists(filePath) {
  try {
    const info = await stat(filePath);
    return info.isFile();
  } catch {
    return false;
  }
}

async function readJsonFile(filePath, fallback = {}) {
  if (!(await fileExists(filePath))) return fallback;
  return JSON.parse(await readFile(filePath, 'utf8'));
}

export function isSensitiveEnvKey(key) {
  return SECRET_ENV_KEY_PATTERN.test(String(key));
}

export function envReference(key) {
  return `\${env:${key}}`;
}

function severityRank(severity) {
  return { low: 1, medium: 2, high: 3 }[severity] ?? 0;
}

function highestRisk(findings) {
  return findings.reduce((risk, finding) => (
    severityRank(finding.severity) > severityRank(risk) ? finding.severity : risk
  ), 'low');
}

function addFinding(findings, id, severity, message, recommendation) {
  findings.push({ id, severity, message, recommendation });
}

function firstPackageSpec(command, args) {
  if (!PACKAGE_RUNNERS.has(commandBase(command))) return null;
  for (const arg of args) {
    if (!arg || arg.startsWith('-')) continue;
    return arg;
  }
  return null;
}

function isPinnedPackageSpec(spec) {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || /^[A-Za-z]:/.test(spec)) return true;
  if (spec.startsWith('@')) return spec.indexOf('@', 1) !== -1;
  return spec.includes('@');
}

export function scanMcpServerCommand(server = {}) {
  const command = server.command ?? null;
  const args = normalizeArgs(server.args);
  const url = server.url ?? server.origin ?? null;
  const safeUrl = redactUrl(url);
  const env = normalizeEnv(server.env);
  const envKeys = Object.keys(env);
  const sensitiveEnvKeys = envKeys.filter(isSensitiveEnvKey);
  const findings = [];

  if (url) {
    addFinding(
      findings,
      String(url).startsWith('https://') ? 'remote_http_transport' : 'insecure_remote_http_transport',
      String(url).startsWith('https://') ? 'medium' : 'high',
      `MCP server uses remote HTTP transport: ${safeUrl}`,
      'Prefer localhost during development; require TLS and explicit authorization for remote servers.'
    );
  }

  if (!command && !url) {
    addFinding(findings, 'missing_server_entrypoint', 'high', 'MCP server has no command or URL.', 'Add an explicit stdio command or HTTP URL before import.');
  }

  const base = commandBase(command);
  if (PACKAGE_RUNNERS.has(base)) {
    addFinding(
      findings,
      'package_runner_execution',
      'high',
      `MCP server runs through package runner ${base}.`,
      'Pin the package version and run it through an isolated HCP wrapper before exposing secrets.'
    );
  }
  if (SHELL_COMMANDS.has(base)) {
    addFinding(
      findings,
      'shell_execution',
      'high',
      `MCP server starts through shell command ${base}.`,
      'Avoid shell expansion; use an explicit executable plus argument array.'
    );
  }
  if (args.includes('-y') || args.includes('--yes')) {
    addFinding(
      findings,
      'auto_yes_package_install',
      'high',
      'MCP command enables non-interactive package execution.',
      'Remove auto-yes flags and pin reviewed package versions.'
    );
  }

  const packageSpec = firstPackageSpec(command, args);
  if (packageSpec && !isPinnedPackageSpec(packageSpec)) {
    addFinding(
      findings,
      'unpinned_package',
      'high',
      `Package runner target is not version pinned: ${packageSpec}`,
      'Use an exact package version such as package@1.2.3.'
    );
  }

  if (args.some((arg) => /^https?:\/\//i.test(arg))) {
    addFinding(
      findings,
      'network_argument',
      'medium',
      'MCP command arguments include a network URL.',
      'Review remote endpoints and prefer explicit allowlists.'
    );
  }

  if (sensitiveEnvKeys.length > 0) {
    addFinding(
      findings,
      'sensitive_env_present',
      'high',
      `Sensitive environment variables are present: ${sensitiveEnvKeys.join(', ')}`,
      'Replace raw values with env references and keep secrets out of shared config.'
    );
  }

  if (findings.length === 0) {
    addFinding(findings, 'no_obvious_local_command_risk', 'low', 'No obvious local command risk was detected.', 'Still review provider code and manifest scopes before enabling it.');
  }

  return {
    transport: url ? 'http' : 'stdio',
    risk: highestRisk(findings),
    command: command ?? null,
    args,
    url: safeUrl,
    env_keys: envKeys,
    sensitive_env_keys: sensitiveEnvKeys,
    findings
  };
}

function serverEntries(config = {}) {
  if (config.mcpServers && typeof config.mcpServers === 'object') {
    return Object.entries(config.mcpServers).map(([id, server]) => [id, server]);
  }
  if (Array.isArray(config.servers)) {
    return config.servers.map((server, index) => [server.id ?? server.name ?? `server_${index + 1}`, server]);
  }
  return [];
}

function toGovernedEnv(env = {}) {
  return Object.fromEntries(Object.entries(normalizeEnv(env)).map(([key, value]) => [
    key,
    isSensitiveEnvKey(key) ? envReference(key) : value
  ]));
}

function toEnvRefRecords(env = {}) {
  return Object.keys(normalizeEnv(env)).filter(isSensitiveEnvKey).sort().map((key) => ({
    name: key,
    ref: `env:${key}`,
    expression: envReference(key),
    sensitive: isSensitiveEnvKey(key),
    required: true
  }));
}

export function importMcpConfig(config = {}, { source = null, target = null } = {}) {
  const servers = serverEntries(config).map(([id, server]) => {
    const risk = scanMcpServerCommand(server);
    return {
      id,
      transport: risk.transport,
      command: server.command ?? null,
      args: normalizeArgs(server.args),
      url: risk.url,
      env: toGovernedEnv(server.env),
      env_refs: toEnvRefRecords(server.env),
      risk
    };
  });

  return {
    kind: 'hcp.mcp.governance_config',
    version: '0.1',
    source,
    target,
    secrets_model: {
      strategy: 'env_reference',
      syntax: '${env:NAME}',
      raw_values: 'redacted'
    },
    servers
  };
}

function jsonConfigFromGoverned(imported) {
  const mcpServers = {};
  for (const server of imported.servers ?? []) {
    const exported = {};
    if (server.transport === 'http' && server.url) {
      exported.url = server.url;
    } else {
      exported.command = server.command;
      exported.args = normalizeArgs(server.args);
    }
    exported.env = server.env ?? Object.fromEntries((server.env_refs ?? []).map((entry) => [entry.name, entry.expression ?? envReference(entry.name)]));
    mcpServers[server.id] = exported;
  }
  return { mcpServers };
}

function tomlString(value) {
  return JSON.stringify(String(value));
}

function tomlArray(values = []) {
  return `[${normalizeArgs(values).map(tomlString).join(', ')}]`;
}

function tomlInlineEnv(env = {}) {
  const entries = Object.entries(env);
  if (entries.length === 0) return null;
  return `{ ${entries.map(([key, value]) => `${tomlString(key)} = ${tomlString(value)}`).join(', ')} }`;
}

function toCodexToml(imported) {
  const lines = [HCP_TOML_BLOCK_START];
  for (const server of imported.servers ?? []) {
    lines.push(`[mcp_servers.${tomlString(server.id)}]`);
    if (server.transport === 'http' && server.url) {
      lines.push(`url = ${tomlString(server.url)}`);
    } else {
      lines.push(`command = ${tomlString(server.command ?? '')}`);
      lines.push(`args = ${tomlArray(server.args)}`);
    }
    const env = server.env ?? Object.fromEntries((server.env_refs ?? []).map((entry) => [entry.name, entry.expression ?? envReference(entry.name)]));
    const inlineEnv = tomlInlineEnv(env);
    if (inlineEnv) lines.push(`env = ${inlineEnv}`);
    lines.push('');
  }
  lines.push(HCP_TOML_BLOCK_END);
  return lines.join('\n');
}

function replaceManagedTomlBlock(existing, block) {
  const pattern = new RegExp(`${HCP_TOML_BLOCK_START}[\\s\\S]*?${HCP_TOML_BLOCK_END}\\n?`, 'm');
  const trimmed = existing.replace(pattern, '').trimEnd();
  return `${trimmed}${trimmed ? '\n\n' : ''}${block}\n`;
}

export function exportMcpConfig(config = {}, { target = 'generic', format = null } = {}) {
  const imported = config.kind === 'hcp.mcp.governance_config' ? config : importMcpConfig(config, { target });
  if (format === 'toml' || target === 'codex') {
    return {
      target,
      format: 'toml',
      toml: toCodexToml(imported),
      notes: [
        'Codex config.toml output is wrapped in an HCP-managed block.',
        'Sensitive environment values are exported as references; non-sensitive values stay literal.'
      ]
    };
  }

  return {
    target,
    ...jsonConfigFromGoverned(imported),
    notes: [
      'Sensitive environment values are exported as references; non-sensitive values stay literal.',
      'Review each server risk report before enabling the config in an MCP client.'
    ]
  };
}

export function doctorMcpConfig(config = {}, options = {}) {
  const imported = config.kind === 'hcp.mcp.governance_config' ? config : importMcpConfig(config, options);
  const servers = (imported.servers ?? []).map((server) => ({
    ...server,
    risk: scanMcpServerCommand(server)
  }));
  const risk_counts = servers.reduce((counts, server) => {
    counts[server.risk.risk] = (counts[server.risk.risk] ?? 0) + 1;
    return counts;
  }, {});
  return {
    kind: 'hcp.mcp.config_doctor',
    total_servers: servers.length,
    risk_counts,
    secrets_model: imported.secrets_model,
    servers: servers.map((server) => ({
      id: server.id,
      transport: server.transport,
      risk: server.risk.risk,
      env_refs: server.env_refs,
      findings: server.risk.findings
    }))
  };
}

export function discoverMcpConfigTargets({
  workspace = process.cwd(),
  home = os.homedir(),
  platform = process.platform,
  env = process.env
} = {}) {
  const appData = env.APPDATA ?? path.join(home, 'AppData', 'Roaming');
  return [
    {
      target: 'claude',
      scope: 'user',
      format: 'json',
      path: platform === 'darwin'
        ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
        : platform === 'win32'
          ? path.join(appData, 'Claude', 'claude_desktop_config.json')
          : path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
      write_supported: true
    },
    {
      target: 'cursor',
      scope: 'workspace',
      format: 'json',
      path: path.join(workspace, '.cursor', 'mcp.json'),
      write_supported: true
    },
    {
      target: 'cursor',
      scope: 'user',
      format: 'json',
      path: path.join(home, '.cursor', 'mcp.json'),
      write_supported: true
    },
    {
      target: 'codex',
      scope: 'workspace',
      format: 'toml',
      path: path.join(workspace, '.codex', 'config.toml'),
      write_supported: true
    },
    {
      target: 'codex',
      scope: 'user',
      format: 'toml',
      path: path.join(home, '.codex', 'config.toml'),
      write_supported: true
    }
  ];
}

export async function inspectMcpConfigTargets(options = {}) {
  const targets = discoverMcpConfigTargets(options);
  return {
    kind: 'hcp.mcp.config_discovery',
    workspace: options.workspace ?? process.cwd(),
    targets: await Promise.all(targets.map(async (target) => ({
      ...target,
      exists: await fileExists(target.path)
    })))
  };
}

export async function backupMcpConfig(configPath, { clock = new Date() } = {}) {
  if (!(await fileExists(configPath))) {
    return { source: configPath, backup_path: null, existed: false };
  }
  const backupPath = `${configPath}.bak.${timestampForFile(clock)}`;
  await mkdir(path.dirname(backupPath), { recursive: true });
  // Client configs routinely hold raw tokens; backups are owner-only.
  await writeFile(backupPath, await readFile(configPath), { mode: 0o600 });
  return { source: configPath, backup_path: backupPath, existed: true };
}

function selectedTarget({ target = 'generic', scope = null, configPath = null, workspace = process.cwd() } = {}) {
  if (scope && !MCP_CONFIG_SCOPES.has(scope)) {
    throw new Error(`Unknown MCP config scope: ${scope}`);
  }
  if (configPath) {
    return {
      target,
      scope: scope ?? 'explicit',
      format: configPath.endsWith('.toml') ? 'toml' : 'json',
      path: configPath,
      write_supported: true
    };
  }
  const candidates = discoverMcpConfigTargets({ workspace }).filter((entry) => entry.target === target);
  const selected = candidates.find((entry) => !scope || entry.scope === scope);
  if (!selected && scope) {
    throw new Error(`MCP config target ${target} does not support scope: ${scope}`);
  }
  return selected ?? candidates[0] ?? null;
}

export async function writeMcpClientConfig(config = {}, {
  target = 'generic',
  scope = null,
  configPath = null,
  workspace = process.cwd(),
  dryRun = false,
  yes = false,
  protect = false,
  policyPath = null,
  vaultPath = null,
  proxyCommand = null,
  proxyArgsPrefix = null,
  clock = new Date()
} = {}) {
  if (protect) {
    return protectMcpClientConfig(config, {
      target,
      scope,
      configPath,
      workspace,
      dryRun,
      yes,
      policyPath,
      vaultPath,
      proxyCommand,
      proxyArgsPrefix,
      clock
    });
  }
  const selected = selectedTarget({ target, scope, configPath, workspace });
  if (!selected) {
    throw new Error(`Unknown MCP config target: ${target}`);
  }
  if (!dryRun && yes !== true) {
    throw new Error('Refusing to write MCP client config without --yes. Use --dry-run to preview.');
  }

  const imported = config.kind === 'hcp.mcp.governance_config' ? config : importMcpConfig(config, { target });
  let nextContent;
  if (selected.format === 'toml') {
    const existing = await fileExists(selected.path) ? await readFile(selected.path, 'utf8') : '';
    nextContent = replaceManagedTomlBlock(existing, toCodexToml(imported));
  } else {
    const existing = await readJsonFile(selected.path, {});
    const exported = jsonConfigFromGoverned(imported);
    nextContent = `${JSON.stringify({
      ...existing,
      mcpServers: {
        ...(existing.mcpServers ?? {}),
        ...exported.mcpServers
      }
    }, null, 2)}\n`;
  }

  if (dryRun) {
    return {
      target: selected.target,
      scope: selected.scope,
      path: selected.path,
      format: selected.format,
      dry_run: true,
      would_write: true,
      backup: null,
      bytes: Buffer.byteLength(nextContent, 'utf8')
    };
  }

  await mkdir(path.dirname(selected.path), { recursive: true });
  const backup = await backupMcpConfig(selected.path, { clock });
  await writeFile(selected.path, nextContent, 'utf8');
  return {
    target: selected.target,
    scope: selected.scope,
    path: selected.path,
    format: selected.format,
    dry_run: false,
    written: true,
    backup,
    bytes: Buffer.byteLength(nextContent, 'utf8')
  };
}

function isAlreadyProxiedServer(server = {}, policyPath = null) {
  const args = normalizeArgs(server.args);
  const hasMcpProxy = args.some((arg, index) => arg === 'mcp' && args[index + 1] === 'proxy');
  if (!hasMcpProxy) return false;
  if (!policyPath) return true;
  return args.includes(policyPath);
}

const HCP_GITIGNORE_ENTRIES = [
  '.hcp/secrets.json',
  '.hcp/audit.jsonl',
  '.hcp/backups/',
  '*.json.bak.*',
  '*.toml.bak.*'
];

// .hcp/secrets.json and client-config backups contain raw credentials. When
// the workspace is a git repository, make sure they cannot be committed.
async function ensureHcpGitignore(workspace) {
  if (!existsSync(path.join(workspace, '.git'))) {
    return { updated: false, reason: 'not_a_git_repository' };
  }
  const gitignorePath = path.join(workspace, '.gitignore');
  const existing = (await fileExists(gitignorePath)) ? await readFile(gitignorePath, 'utf8') : '';
  const lines = new Set(existing.split(/\r?\n/).map((line) => line.trim()));
  const missing = lines.has('.hcp/') || lines.has('.hcp')
    ? HCP_GITIGNORE_ENTRIES.filter((entry) => !entry.startsWith('.hcp/') && !lines.has(entry))
    : HCP_GITIGNORE_ENTRIES.filter((entry) => !lines.has(entry));
  if (missing.length === 0) return { updated: false, path: gitignorePath, reason: 'already_present' };
  const prefix = existing.length === 0 || existing.endsWith('\n') ? '' : '\n';
  await writeFile(gitignorePath, `${existing}${prefix}\n# HCP local secrets, audit log and config backups\n${missing.join('\n')}\n`, 'utf8');
  return { updated: true, path: gitignorePath, added: missing };
}

function defaultBackupSlotPaths(workspace, selected) {
  const backupsDir = path.join(workspace, '.hcp', 'backups');
  const slotName = `${selected.target}-${selected.scope}`;
  return {
    backupsDir,
    backupFile: path.join(backupsDir, `${slotName}.backup`),
    metaFile: path.join(backupsDir, `${slotName}.meta.json`)
  };
}

export async function protectMcpClientConfig(config = null, {
  target = 'cursor',
  scope = null,
  configPath = null,
  workspace = process.cwd(),
  dryRun = false,
  yes = false,
  policyPath = null,
  vaultPath = null,
  auditLogPath = null,
  proxyCommand = 'npx',
  proxyArgsPrefix = ['-y', HCP_RUNTIME_PACKAGE_SPEC],
  outputPolicy = {},
  approvalMode = undefined,
  clock = new Date()
} = {}) {
  const selected = selectedTarget({ target, scope, configPath, workspace });
  if (!selected) {
    throw new Error(`Unknown MCP config target: ${target}`);
  }
  if (!dryRun && yes !== true) {
    throw new Error('Refusing to protect MCP client config without --yes. Use --dry-run to preview.');
  }

  const resolvedPolicyPath = policyPath
    ? (path.isAbsolute(policyPath) ? policyPath : path.resolve(workspace, policyPath))
    : path.join(workspace, '.hcp', 'policy.json');
  const resolvedVaultPath = vaultPath
    ? (path.isAbsolute(vaultPath) ? vaultPath : path.resolve(workspace, vaultPath))
    : path.join(workspace, '.hcp', 'secrets.json');
  const resolvedAuditLogPath = auditLogPath
    ? (path.isAbsolute(auditLogPath) ? auditLogPath : path.resolve(workspace, auditLogPath))
    : path.join(workspace, '.hcp', 'audit.jsonl');

  const existingFileExists = await fileExists(selected.path);
  let sourceConfig = config;
  if (!sourceConfig || (typeof sourceConfig === 'object' && Object.keys(sourceConfig).length === 0)) {
    if (selected.format === 'json' && existingFileExists) {
      sourceConfig = await readJsonFile(selected.path, {});
    } else {
      sourceConfig = {};
    }
  }

  // Any server already routed through `mcp proxy` (whatever policy file it
  // points at) is left untouched. Re-wrapping it would record the proxy
  // itself as an upstream server and make the proxy spawn itself.
  const rawEntries = serverEntries(sourceConfig);
  const rawServersForSecretize = {};
  const alreadyProtected = [];
  for (const [id, srv] of rawEntries) {
    if (isAlreadyProxiedServer(srv)) {
      alreadyProtected.push(id);
    } else {
      rawServersForSecretize[id] = srv;
    }
  }

  let imported;
  if (sourceConfig.kind === 'hcp.mcp.governance_config') {
    imported = {
      ...sourceConfig,
      servers: (sourceConfig.servers ?? []).filter((server) => {
        if (!isAlreadyProxiedServer(server)) return true;
        alreadyProtected.push(server.id);
        return false;
      })
    };
  } else {
    imported = Object.keys(rawServersForSecretize).length > 0
      ? importMcpConfig({ mcpServers: rawServersForSecretize }, { target })
      : { servers: [] };
  }

  if ((imported.servers ?? []).length === 0) {
    return {
      kind: 'hcp.mcp.config_protect',
      target: selected.target,
      scope: selected.scope,
      path: selected.path,
      format: selected.format,
      dry_run: dryRun,
      written: false,
      protected_servers: [],
      already_protected: alreadyProtected,
      policy_path: resolvedPolicyPath,
      message: alreadyProtected.length > 0
        ? 'All MCP servers in this config are already protected by hcp mcp proxy; nothing to do.'
        : 'No MCP servers found to protect.'
    };
  }

  const policyServers = {};
  const rewrittenGovernedServers = [];
  const prefixArgs = Array.isArray(proxyArgsPrefix) ? proxyArgsPrefix.map(String) : [];

  for (const server of imported.servers ?? []) {
    policyServers[server.id] = {
      id: server.id,
      provider_id: `mcp.${server.id}`,
      transport: server.transport,
      ...(server.command ? { command: server.command, args: normalizeArgs(server.args) } : {}),
      ...(server.url ? { origin: server.url } : {}),
      ...(server.env && Object.keys(server.env).length > 0 ? { env: server.env } : {})
    };

    const nonSensitiveEnv = Object.fromEntries(
      Object.entries(server.env ?? {}).filter(([key]) => !isSensitiveEnvKey(key))
    );

    rewrittenGovernedServers.push({
      id: server.id,
      transport: 'stdio',
      command: proxyCommand ?? 'npx',
      args: [
        ...prefixArgs,
        'mcp',
        'proxy',
        '--config',
        resolvedPolicyPath,
        '--server',
        server.id
      ],
      env: nonSensitiveEnv,
      env_refs: []
    });
  }

  const existingPolicy = await readJsonFile(resolvedPolicyPath, null);
  const mergedPolicyServers = Object.fromEntries(
    Object.entries({
      ...(existingPolicy?.servers ?? {}),
      ...policyServers
    }).filter(([, server]) => !isAlreadyProxiedServer(server))
  );
  const policyDocument = createDefaultMcpProxyPolicy({
    servers: mergedPolicyServers,
    auditLogPath: resolvedAuditLogPath,
    secretsFile: resolvedVaultPath,
    outputPolicy: {
      ...(existingPolicy?.output_policy ?? {}),
      ...outputPolicy
    },
    grants: existingPolicy?.grants ?? [],
    approvalMode: approvalMode ?? existingPolicy?.approval_mode ?? undefined,
    ...(existingPolicy?.auto_grant !== undefined ? { autoGrant: existingPolicy.auto_grant } : {})
  });

  let nextClientContent;
  const rewrittenImported = {
    ...imported,
    servers: rewrittenGovernedServers
  };
  if (selected.format === 'toml') {
    const existing = existingFileExists ? await readFile(selected.path, 'utf8') : '';
    nextClientContent = replaceManagedTomlBlock(existing, toCodexToml(rewrittenImported));
  } else {
    const existing = existingFileExists ? await readJsonFile(selected.path, {}) : {};
    const exported = jsonConfigFromGoverned(rewrittenImported);
    nextClientContent = `${JSON.stringify({
      ...existing,
      mcpServers: {
        ...(existing.mcpServers ?? {}),
        ...exported.mcpServers
      }
    }, null, 2)}\n`;
  }

  if (dryRun) {
    return {
      kind: 'hcp.mcp.config_protect',
      target: selected.target,
      scope: selected.scope,
      path: selected.path,
      format: selected.format,
      dry_run: true,
      would_write: true,
      protected_servers: rewrittenGovernedServers.map((s) => s.id),
      policy_path: resolvedPolicyPath,
      vault_path: resolvedVaultPath,
      audit_log_path: resolvedAuditLogPath,
      backup: null,
      bytes: Buffer.byteLength(nextClientContent, 'utf8')
    };
  }

  // The restore slot keeps the config as it was before the FIRST protect.
  // A later protect (e.g. after adding a server) must not overwrite it with an
  // already-protected config; for JSON clients the newly protected servers'
  // original entries are merged into the preserved backup instead.
  const slot = defaultBackupSlotPaths(workspace, selected);
  await mkdir(slot.backupsDir, { recursive: true });
  const timestampBackup = await backupMcpConfig(selected.path, { clock });
  const previousMeta = await readJsonFile(slot.metaFile, null);
  const newlyProtected = rewrittenGovernedServers.map((s) => s.id);
  if (previousMeta && previousMeta.backup_file && (await fileExists(previousMeta.backup_file))) {
    if (selected.format === 'json') {
      const backup = await readJsonFile(previousMeta.backup_file, {});
      const additions = Object.fromEntries(
        newlyProtected
          .filter((id) => rawServersForSecretize[id] !== undefined)
          .map((id) => [id, rawServersForSecretize[id]])
      );
      await writeFile(previousMeta.backup_file, `${JSON.stringify({
        ...backup,
        mcpServers: { ...(backup.mcpServers ?? {}), ...additions }
      }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    }
  } else if (existingFileExists) {
    await writeFile(slot.backupFile, await readFile(selected.path), { mode: 0o600 });
  }
  const firstProtect = !previousMeta;
  await writeFile(slot.metaFile, `${JSON.stringify({
    target: selected.target,
    scope: selected.scope,
    original_path: selected.path,
    existed: firstProtect ? existingFileExists : previousMeta.existed !== false,
    backup_file: firstProtect ? (existingFileExists ? slot.backupFile : null) : (previousMeta.backup_file ?? null),
    timestamp_backup_path: firstProtect ? timestampBackup.backup_path : (previousMeta.timestamp_backup_path ?? timestampBackup.backup_path),
    policy_path: resolvedPolicyPath,
    vault_path: resolvedVaultPath,
    audit_log_path: resolvedAuditLogPath,
    protected_servers: [...new Set([...(previousMeta?.protected_servers ?? []), ...newlyProtected])],
    protected_at: firstProtect ? clock.toISOString() : (previousMeta.protected_at ?? clock.toISOString()),
    updated_at: clock.toISOString()
  }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  const gitignore = await ensureHcpGitignore(workspace);

  const secretized = await secretizeMcpConfig(
    { mcpServers: rawServersForSecretize },
    { workspace, vaultPath: resolvedVaultPath, clock }
  );

  await mkdir(path.dirname(resolvedPolicyPath), { recursive: true });
  await writeFile(resolvedPolicyPath, `${JSON.stringify(policyDocument, null, 2)}\n`, 'utf8');

  await mkdir(path.dirname(selected.path), { recursive: true });
  await writeFile(selected.path, nextClientContent, 'utf8');

  return {
    kind: 'hcp.mcp.config_protect',
    target: selected.target,
    scope: selected.scope,
    path: selected.path,
    format: selected.format,
    dry_run: false,
    written: true,
    protected_servers: rewrittenGovernedServers.map((s) => s.id),
    already_protected: alreadyProtected,
    policy_path: resolvedPolicyPath,
    vault: secretized.vault,
    gitignore,
    audit_log_path: resolvedAuditLogPath,
    backup: {
      ...timestampBackup,
      restore_slot: slot.metaFile
    },
    bytes: Buffer.byteLength(nextClientContent, 'utf8')
  };
}

export async function restoreMcpClientConfig({
  target = 'cursor',
  scope = null,
  configPath = null,
  backupPath = null,
  workspace = process.cwd(),
  dryRun = false,
  yes = false
} = {}) {
  const selected = selectedTarget({ target, scope, configPath, workspace });
  if (!selected) {
    throw new Error(`Unknown MCP config target: ${target}`);
  }
  if (!dryRun && yes !== true) {
    throw new Error('Refusing to restore MCP client config without --yes. Use --dry-run to preview.');
  }

  const slot = defaultBackupSlotPaths(workspace, selected);
  let resolvedBackupFile = backupPath
    ? (path.isAbsolute(backupPath) ? backupPath : path.resolve(workspace, backupPath))
    : null;
  let existedBeforeProtect = true;

  if (!resolvedBackupFile && (await fileExists(slot.metaFile))) {
    const meta = await readJsonFile(slot.metaFile, {});
    existedBeforeProtect = meta.existed !== false;
    if (meta.backup_file && (await fileExists(meta.backup_file))) {
      resolvedBackupFile = meta.backup_file;
    } else if (meta.timestamp_backup_path && (await fileExists(meta.timestamp_backup_path))) {
      resolvedBackupFile = meta.timestamp_backup_path;
    }
  }

  if (!resolvedBackupFile && existedBeforeProtect) {
    const dir = path.dirname(selected.path);
    const base = path.basename(selected.path);
    try {
      const files = await readdir(dir);
      const candidates = files
        .filter((name) => name.startsWith(`${base}.bak.`))
        .sort();
      if (candidates.length > 0) {
        resolvedBackupFile = path.join(dir, candidates[candidates.length - 1]);
      }
    } catch {
      // ignore missing directory
    }
  }

  if (existedBeforeProtect && (!resolvedBackupFile || !(await fileExists(resolvedBackupFile)))) {
    throw new Error(`No MCP config backup found to restore for ${selected.path}`);
  }

  if (dryRun) {
    return {
      kind: 'hcp.mcp.config_restore',
      target: selected.target,
      scope: selected.scope,
      path: selected.path,
      dry_run: true,
      would_restore: true,
      existed_before_protect: existedBeforeProtect,
      restored_from: resolvedBackupFile
    };
  }

  if (!existedBeforeProtect) {
    await rm(selected.path, { force: true });
  } else {
    const originalBytes = await readFile(resolvedBackupFile);
    await mkdir(path.dirname(selected.path), { recursive: true });
    await writeFile(selected.path, originalBytes);
  }
  // Close the restore slot so the next protect captures a fresh original.
  if (!backupPath) {
    await rm(slot.metaFile, { force: true });
    await rm(slot.backupFile, { force: true });
  }

  return {
    kind: 'hcp.mcp.config_restore',
    target: selected.target,
    scope: selected.scope,
    path: selected.path,
    dry_run: false,
    restored: true,
    existed_before_protect: existedBeforeProtect,
    restored_from: resolvedBackupFile
  };
}

export async function secretizeMcpConfig(config = {}, {
  workspace = process.cwd(),
  vaultPath = path.join(workspace, '.hcp', 'secrets.json'),
  clock = new Date()
} = {}) {
  const imported = importMcpConfig(config, { source: 'secretize' });
  const vault = await readJsonFile(vaultPath, { version: '0.1', secrets: {} });
  for (const [id, server] of serverEntries(config)) {
    for (const [name, value] of Object.entries(normalizeEnv(server.env))) {
      if (!isSensitiveEnvKey(name)) continue;
      vault.secrets[`mcp.${id}.${name}`] = {
        value,
        ref: `env:${name}`,
        updated_at: clock.toISOString()
      };
    }
  }
  await mkdir(path.dirname(vaultPath), { recursive: true });
  await writeFile(vaultPath, `${JSON.stringify(vault, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  return {
    config: imported,
    vault: {
      path: vaultPath,
      storage: 'local_private_file',
      secret_count: Object.keys(vault.secrets).length,
      warning: 'Local vault is intended for developer workstations; use an OS/team secret manager for shared production environments.'
    }
  };
}
