import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { HcpRuntime, createFilesystemProvider } from '../src/index.js';

const workspace = await mkdtemp(path.join(os.tmpdir(), 'hcp-datapipe-demo-'));

try {
  await writeFile(
    path.join(workspace, 'notes.md'),
    '# Customer Notes\n\nAlice alice@example.com called +1 415 555 0100 about HCP data-flow policy.\n',
    'utf8'
  );

  const runtime = new HcpRuntime();
  await runtime.registerProvider(createFilesystemProvider({ workspace }));

  const principal = 'user:alex';
  runtime.grantCreate({
    principal,
    scopes: ['filesystem:read'],
    resources: ['file:notes.md'],
    capabilities: ['filesystem.file.read']
  });
  runtime.grantCreate({
    principal,
    scopes: ['filesystem:write'],
    resources: ['file:out/redacted.md'],
    capabilities: ['filesystem.file.write']
  });

  const source = await runtime.taskStart('filesystem.file.read', { path: 'notes.md' }, { principal });
  const pipe = await runtime.dataPipe(
    source.result.handle,
    'filesystem.file.write',
    {
      target_field: 'content',
      input: { path: 'out/redacted.md' },
      transform: {
        type: 'summarize',
        max_words: 12,
        redact: ['email', 'phone']
      }
    },
    {
      principal,
      approval: { approved: true, by: 'data-pipe-demo' }
    }
  );

  const written = await readFile(path.join(workspace, 'out/redacted.md'), 'utf8');
  const trace = runtime.auditGetTrace(pipe.task_id);

  console.log(JSON.stringify({
    demo: 'data-pipe',
    source_status: source.status,
    pipe_status: pipe.status,
    written,
    audit_types: trace.audit_entries.map((entry) => entry.type)
  }, null, 2));
  console.log('data-pipe-demo-ok');
} finally {
  await rm(workspace, { recursive: true, force: true });
}
