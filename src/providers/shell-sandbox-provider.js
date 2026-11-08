import { spawn } from 'node:child_process';
import path from 'node:path';
import { InvalidInputError } from '../errors.js';

function normalizeRoot(root) {
  if (!root) throw new InvalidInputError('Shell sandbox provider requires a workspace root');
  return path.resolve(root);
}

function safeCwd(root, userCwd = '.') {
  if (typeof userCwd !== 'string') {
    throw new InvalidInputError('cwd must be a string', { cwd: userCwd });
  }
  const resolved = path.resolve(root, userCwd);
  const relative = path.relative(root, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new InvalidInputError('cwd escapes shell sandbox workspace', { cwd: userCwd, root });
  }
  return resolved;
}

function validateCommand(command, allowedCommands) {
  if (typeof command !== 'string' || command.length === 0) {
    throw new InvalidInputError('command must be a non-empty string', { command });
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(command)) {
    throw new InvalidInputError('command contains unsupported characters', { command });
  }
  if (!allowedCommands.has(command)) {
    throw new InvalidInputError('command is not allowed by shell sandbox provider', {
      command,
      allowed_commands: [...allowedCommands]
    });
  }
}

function validateArgs(args = []) {
  if (!Array.isArray(args)) {
    throw new InvalidInputError('args must be an array', { args });
  }
  for (const arg of args) {
    if (typeof arg !== 'string') {
      throw new InvalidInputError('args must contain only strings', { args });
    }
  }
  return args;
}

function defaultExecImpl({ command, args, cwd, timeoutMs, maxOutputBytes }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      shell: false,
      windowsHide: true
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      reject(new InvalidInputError('shell command timed out', { command, timeout_ms: timeoutMs }));
    }, timeoutMs);

    const collect = (current, chunk) => `${current}${chunk.toString()}`.slice(0, maxOutputBytes);
    child.stdout.on('data', (chunk) => {
      stdout = collect(stdout, chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr = collect(stderr, chunk);
    });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ exit_code: code, signal, stdout, stderr });
    });
  });
}

export function createShellSandboxProvider({
  workspace,
  allowedCommands = [],
  execImpl = defaultExecImpl,
  timeoutMs = 5000,
  maxOutputBytes = 64 * 1024
} = {}) {
  const root = normalizeRoot(workspace);
  const allowedCommandSet = new Set(allowedCommands);
  if (typeof execImpl !== 'function') {
    throw new InvalidInputError('shell sandbox provider requires exec implementation');
  }

  return {
    async manifest() {
      return {
        provider: {
          id: 'shell.sandbox',
          version: '0.1.0',
          title: 'Shell Sandbox Provider',
          description: 'Run allowlisted commands inside a configured workspace without shell expansion.',
          sandbox: {
            cwd: root,
            allowed_commands: [...allowedCommandSet],
            shell: false
          }
        },
        capabilities: [
          {
            id: 'shell.command.run',
            version: '0.1.0',
            title: 'Run sandboxed command',
            description: 'Runs an explicitly allowlisted command with string args inside the configured workspace.',
            intents: ['run command', 'execute sandbox command'],
            input_schema: {
              type: 'object',
              required: ['command'],
              properties: {
                command: { type: 'string' },
                args: { type: 'array', items: { type: 'string' } },
                cwd: { type: 'string', default: '.' }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                exit_code: { type: 'number' },
                signal: { type: ['string', 'null'] },
                stdout_handle: { type: 'string' },
                stderr_handle: { type: 'string' }
              }
            },
            effects: {
              kind: 'execute',
              risk: 'high',
              dry_run: 'unsupported',
              idempotency: 'none'
            },
            security: {
              required_scopes: ['shell:run'],
              resource_model: {
                type: 'canonical_provider_resource',
                format: 'shell:<command>'
              },
              data_in: ['command_args'],
              data_out: ['process_output'],
              approval: {
                default: 'required'
              }
            }
          }
        ]
      };
    },

    async health() {
      return {
        status: 'ok',
        root,
        allowed_commands: [...allowedCommandSet],
        shell: false
      };
    },

    resourceFor({ input }) {
      validateCommand(input.command, allowedCommandSet);
      safeCwd(root, input.cwd ?? '.');
      validateArgs(input.args ?? []);
      return `shell:${input.command}`;
    },

    async invoke({ input, runtime, task }) {
      validateCommand(input.command, allowedCommandSet);
      const cwd = safeCwd(root, input.cwd ?? '.');
      const args = validateArgs(input.args ?? []);
      const result = await execImpl({
        command: input.command,
        args,
        cwd,
        timeoutMs,
        maxOutputBytes
      });
      const stdout = String(result.stdout ?? '').slice(0, maxOutputBytes);
      const stderr = String(result.stderr ?? '').slice(0, maxOutputBytes);
      const stdoutHandle = runtime.dataPut(stdout, {
        principal: task.principal,
        capability: 'shell.command.run',
        resource: `shell:${input.command}`,
        task_id: task.task_id,
        data_class: ['process_output'],
        content_type: 'text/plain',
        source: 'stdout'
      });
      const stderrHandle = runtime.dataPut(stderr, {
        principal: task.principal,
        capability: 'shell.command.run',
        resource: `shell:${input.command}`,
        task_id: task.task_id,
        data_class: ['process_output'],
        content_type: 'text/plain',
        source: 'stderr'
      });

      return {
        exit_code: result.exit_code ?? 0,
        signal: result.signal ?? null,
        stdout_handle: stdoutHandle,
        stderr_handle: stderrHandle
      };
    }
  };
}
