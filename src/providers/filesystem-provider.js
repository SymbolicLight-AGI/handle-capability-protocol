import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { InvalidInputError } from '../errors.js';

function normalizeRoot(root) {
  if (!root) throw new InvalidInputError('Filesystem provider requires a workspace root');
  return path.resolve(root);
}

function normalizeUserPath(userPath) {
  return userPath.replace(/\\/g, '/');
}

function safePath(root, userPath = '.') {
  if (typeof userPath !== 'string') {
    throw new InvalidInputError('path must be a string', { userPath });
  }
  const normalizedPath = normalizeUserPath(userPath);
  if (/^[A-Za-z]:(?:\/|$)/.test(normalizedPath) || normalizedPath.startsWith('//')) {
    throw new InvalidInputError('path escapes filesystem provider workspace', { path: userPath, root });
  }
  const resolved = path.resolve(root, normalizedPath);
  const relative = path.relative(root, resolved);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new InvalidInputError('path escapes filesystem provider workspace', { path: userPath, root });
  }
  return resolved;
}

function relativePath(root, target) {
  return path.relative(root, target).replace(/\\/g, '/') || '.';
}

function resourceForPath(root, userPath = '.') {
  return `file:${relativePath(root, safePath(root, userPath))}`;
}

async function listRecursive(root, dir, depth, maxDepth, out) {
  if (depth > maxDepth) return;
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const relative = path.relative(root, full).replace(/\\/g, '/');
    const st = await stat(full);
    out.push({
      path: relative || '.',
      type: entry.isDirectory() ? 'directory' : 'file',
      bytes: st.size,
      modified_at: st.mtime.toISOString()
    });
    if (entry.isDirectory()) {
      await listRecursive(root, full, depth + 1, maxDepth, out);
    }
  }
}

export function createFilesystemProvider({ workspace }) {
  const root = normalizeRoot(workspace);

  return {
    async manifest() {
      return {
        provider: {
          id: 'local.filesystem',
          version: '0.1.0',
          title: 'Local Filesystem Provider',
          sandbox: {
            filesystem: {
              read: [root],
              write: [root]
            }
          }
        },
        capabilities: [
          {
            id: 'filesystem.file.list',
            version: '0.1.0',
            title: 'List workspace files',
            description: 'Lists files under the configured workspace root without escaping the sandbox.',
            intents: ['list files', 'inspect workspace', 'repo snapshot', '查看文件', '列出目录'],
            input_schema: {
              type: 'object',
              properties: {
                path: { type: 'string', default: '.' },
                max_depth: { type: 'integer', minimum: 0, default: 2 }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                files: { type: 'array' }
              }
            },
            effects: {
              kind: 'read',
              risk: 'low',
              dry_run: 'unsupported',
              idempotency: 'supported'
            },
            security: {
              required_scopes: ['filesystem:read'],
              data_in: ['path'],
              data_out: ['workspace_metadata']
            }
          },
          {
            id: 'filesystem.file.read',
            version: '0.1.0',
            title: 'Read workspace file',
            description: 'Reads a UTF-8 file from the configured workspace root and returns the content as a vault handle.',
            intents: ['read file', 'open document', 'inspect markdown', '读取文件', '查看文档'],
            input_schema: {
              type: 'object',
              required: ['path'],
              properties: {
                path: { type: 'string' }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                handle: { type: 'string' },
                bytes: { type: 'integer' },
                summary: { type: 'string' }
              }
            },
            effects: {
              kind: 'read',
              risk: 'low',
              dry_run: 'unsupported',
              idempotency: 'supported'
            },
            security: {
              required_scopes: ['filesystem:read'],
              data_in: ['path'],
              data_out: ['file_content', 'internal']
            }
          },
          {
            id: 'filesystem.file.write',
            version: '0.1.0',
            title: 'Write workspace file',
            description: 'Writes a UTF-8 file under the configured workspace root. Parent directories are created automatically.',
            intents: ['write file', 'create document', 'save generated output', '写入文件', '创建文档'],
            input_schema: {
              type: 'object',
              required: ['path', 'content'],
              properties: {
                path: { type: 'string' },
                content: { type: 'string' },
                overwrite: { type: 'boolean', default: true }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                path: { type: 'string' },
                bytes: { type: 'integer' },
                handle: { type: 'string' }
              }
            },
            effects: {
              kind: 'write',
              risk: 'medium',
              dry_run: 'supported',
              idempotency: 'supported'
            },
            security: {
              required_scopes: ['filesystem:write'],
              data_in: ['user_supplied_text', 'file_content', 'internal'],
              data_out: ['workspace_metadata'],
              approval: {
                default: 'required'
              }
            }
          }
        ]
      };
    },

    resourceFor({ capability, input }) {
      switch (capability.id) {
        case 'filesystem.file.list':
        case 'filesystem.file.read':
        case 'filesystem.file.write':
          return resourceForPath(root, input.path ?? '.');
        default:
          return null;
      }
    },

    async health() {
      try {
        const st = await stat(root);
        return { status: st.isDirectory() ? 'ok' : 'error', root };
      } catch (error) {
        return { status: 'error', root, message: error.message };
      }
    },

    async invoke({ capability, input, options, runtime, task }) {
      switch (capability.id) {
        case 'filesystem.file.list': {
          const target = safePath(root, input.path ?? '.');
          const st = await stat(target);
          if (!st.isDirectory()) {
            throw new InvalidInputError('path must point to a directory for filesystem.file.list', {
              path: input.path
            });
          }
          const files = [];
          await listRecursive(root, target, 0, input.max_depth ?? 2, files);
          return {
            files,
            count: files.length,
            root: '.'
          };
        }

        case 'filesystem.file.read': {
          const target = safePath(root, input.path);
          const relative = relativePath(root, target);
          const content = await readFile(target, 'utf8');
          const handle = runtime.dataPut(content, {
            content_type: 'text/plain; charset=utf-8',
            data_class: ['internal', 'file_content'],
            source: capability.id,
            capability: capability.id,
            principal: options.principal ?? null,
            resource: options.resource ?? `file:${relative}`,
            task_id: task.task_id,
            owner_task_id: task.task_id,
            path: relative
          });
          return {
            handle,
            bytes: Buffer.byteLength(content),
            summary: `${input.path} (${Buffer.byteLength(content)} bytes) stored as ${handle}`
          };
        }

        case 'filesystem.file.write': {
          const target = safePath(root, input.path);
          const relative = relativePath(root, target);
          const content = String(input.content ?? '');

          if (options?.dry_run === true) {
            return {
              dry_run: true,
              path: relative,
              bytes: Buffer.byteLength(content)
            };
          }

          await mkdir(path.dirname(target), { recursive: true });
          await writeFile(target, content, 'utf8');
          const handle = runtime.dataPut(
            {
              path: relative,
              bytes: Buffer.byteLength(content)
            },
            {
              content_type: 'application/json',
              data_class: ['workspace_metadata'],
              source: capability.id,
              capability: capability.id,
              principal: options.principal ?? null,
              resource: options.resource ?? `file:${relative}`,
              task_id: task.task_id,
              owner_task_id: task.task_id
            }
          );
          return {
            path: relative,
            bytes: Buffer.byteLength(content),
            handle
          };
        }

        default:
          throw new InvalidInputError(`Unsupported capability for filesystem provider: ${capability.id}`, {
            capability: capability.id
          });
      }
    }
  };
}
