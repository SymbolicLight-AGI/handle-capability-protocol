import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { HcpRuntime, createFilesystemProvider } from '../src/index.js';

async function withRuntime(fn) {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'hcp-test-'));
  try {
    await writeFile(path.join(workspace, 'doc.md'), '# Hello HCP\n\nThis is a test document.\n', 'utf8');
    const runtime = new HcpRuntime();
    await runtime.registerProvider(createFilesystemProvider({ workspace }));
    await fn({ runtime, workspace });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

function grantReadDoc(runtime, principal = 'user:alex') {
  return runtime.grantCreate({
    principal,
    scopes: ['filesystem:read'],
    resources: ['file:doc.md'],
    capabilities: ['filesystem.file.read']
  });
}

function grantWriteFile(runtime, resource, principal = 'user:alex') {
  return runtime.grantCreate({
    principal,
    scopes: ['filesystem:write'],
    resources: [resource],
    capabilities: ['filesystem.file.write']
  });
}

test('task idempotency returns the original task only for the same authorized request', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    const grant = grantWriteFile(runtime, 'file:out.md');
    const input = { path: 'out.md', content: 'synthetic idempotency fixture' };
    const options = { principal: 'user:alex', approval: { approved: true }, idempotency_key: 'local-test-repeat' };
    const original = await runtime.taskStart('filesystem.file.write', input, options);
    assert.equal(original.status, 'COMPLETED');
    const repeated = await runtime.taskStart('filesystem.file.write', input, options);
    assert.equal(repeated.task_id, original.task_id);
    assert.equal(await readFile(path.join(workspace, 'out.md'), 'utf8'), input.content);
    await assert.rejects(runtime.taskStart('filesystem.file.write', input, { ...options, principal: 'user:other' }), { code: 'IDEMPOTENCY_KEY_CONFLICT' });
    await assert.rejects(runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, options), { code: 'IDEMPOTENCY_KEY_CONFLICT' });
    await assert.rejects(runtime.taskStart('filesystem.file.write', { ...input, content: 'different fixture' }, options), { code: 'IDEMPOTENCY_KEY_CONFLICT' });
    await assert.rejects(runtime.taskStart('filesystem.file.write', input, { ...options, dry_run: true }), { code: 'IDEMPOTENCY_KEY_CONFLICT' });
    runtime.grantRevoke(grant.id);
    await assert.rejects(runtime.taskStart('filesystem.file.write', input, options), { code: 'POLICY_DENIED' });
    assert.equal(await readFile(path.join(workspace, 'out.md'), 'utf8'), input.content);
    assert.ok(runtime.auditEntries.some(event => event.type === 'TASK_IDEMPOTENCY_DENIED' && event.reason === 'GRANT_REVOKED'));
  });
});

test('the bilateral-flow task cache namespace is reserved for the private flow entry point', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    grantWriteFile(runtime, 'file:out.md');
    await assert.rejects(runtime.taskStart('filesystem.file.write', { path: 'out.md', content: 'synthetic fixture' }, {
      principal: 'user:alex', approval: { approved: true }, idempotency_key: 'bilateral-flow:local-test'
    }), { code: 'IDEMPOTENCY_KEY_RESERVED' });
    await assert.rejects(readFile(path.join(workspace, 'out.md')), { code: 'ENOENT' });
    assert.equal(runtime.tasks.size, 0);
  });
});

test('a cache hit cannot replace the canonical resource even when both resources are authorized', async () => {
  let canonical = 'fixture:first', invoked = 0;
  const runtime = new HcpRuntime();
  await runtime.registerProvider({
    async manifest() {
      return { provider: { id: 'cached-alias', version: '1.0.0', title: 'Cached alias fixture' },
        capabilities: [{ id: 'cached-alias.read', version: '1.0.0', title: 'Read synthetic fixture',
          input_schema: { type: 'object' }, output_schema: { type: 'object' },
          effects: { kind: 'read', risk: 'low', dry_run: 'unsupported', idempotency: 'supported' },
          security: { required_scopes: ['fixture:read'], data_in: [] } }] };
    },
    resourceFor() { return canonical; },
    async invoke({ options }) { invoked++; return { resource: options.resource, value: 'synthetic fixture' }; }
  });
  runtime.grantCreate({ principal: 'user:alex', scopes: ['fixture:read'],
    resources: ['fixture:first', 'fixture:second'], capabilities: ['cached-alias.read'] });
  const options = { principal: 'user:alex', idempotency_key: 'cached-alias-fixture' };
  const first = await runtime.taskStart('cached-alias.read', { alias: 'local' }, options);
  assert.equal(first.resource, 'fixture:first');
  canonical = 'fixture:second';
  await assert.rejects(runtime.taskStart('cached-alias.read', { alias: 'local' }, options), { code: 'IDEMPOTENCY_KEY_CONFLICT' });
  assert.equal(invoked, 1);
  assert.ok(runtime.auditEntries.some(event => event.type === 'TASK_IDEMPOTENCY_DENIED' && event.reason === 'CANONICAL_RESOURCE_CHANGED'));
});

test('cap.search finds read capability', async () => {
  await withRuntime(async ({ runtime }) => {
    const results = await runtime.capSearch('read markdown file', { side_effects: 'read_only' });
    assert.ok(results.some((result) => result.capability === 'filesystem.file.read'));
    assert.ok(results.every((result) => result.effect === 'read'));
  });
});

test('cap.search honors tool budget as discovery limit', async () => {
  await withRuntime(async ({ runtime }) => {
    const results = await runtime.capSearch('filesystem file', { tool_budget: 1 });

    assert.equal(results.length, 1);
    assert.ok(results[0].capability.startsWith('filesystem.file.'));
  });
});

test('cap.search withholds capabilities the principal holds no authority for', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);

    const unscoped = await runtime.capSearch('filesystem', { limit: 10 });
    assert.ok(unscoped.some((result) => result.capability === 'filesystem.file.write'));

    const scoped = await runtime.capSearch('filesystem', { limit: 10 }, { principal: 'user:alex' });
    assert.ok(scoped.some((result) => result.capability === 'filesystem.file.read'));
    assert.ok(!scoped.some((result) => result.capability === 'filesystem.file.write'));

    const anonymous = await runtime.capSearch('filesystem', { limit: 10 }, { principal: null, scope_discovery: true });
    assert.equal(anonymous.length, 0);

    const scopedAudit = runtime.auditEntries.filter((entry) => entry.type === 'CAPABILITY_DISCOVERY_SCOPED');
    assert.ok(scopedAudit.length >= 2);
    assert.ok(scopedAudit[0].withheld_capabilities.includes('filesystem.file.write'));
  });
});

test('cap.search discovery scope follows grant revocation', async () => {
  await withRuntime(async ({ runtime }) => {
    const grant = grantReadDoc(runtime);

    const before = await runtime.capSearch('filesystem', { limit: 10 }, { principal: 'user:alex' });
    assert.ok(before.some((result) => result.capability === 'filesystem.file.read'));

    runtime.grantRevoke(grant.id);

    const after = await runtime.capSearch('filesystem', { limit: 10 }, { principal: 'user:alex' });
    assert.ok(!after.some((result) => result.capability === 'filesystem.file.read'));
  });
});

test('task.start reads a file into a handle', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });
    assert.equal(task.status, 'COMPLETED');
    assert.match(task.result.handle, /^h:\/\/vault\//);

    const peek = runtime.dataPeek(task.result.handle, { mode: 'preview' }, { principal: 'user:alex' });
    assert.match(peek.preview, /Hello HCP/);
  });
});

test('taskResult resolves owned handle with task principal by default', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    const result = runtime.taskResult(task.task_id, { resolve_handle: true, mode: 'preview' });

    assert.equal(result.status, 'COMPLETED');
    assert.match(result.result.preview, /Hello HCP/);
  });
});

test('taskResult rejects wrong principal when resolving owned handle', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.throws(
      () => runtime.taskResult(task.task_id, { resolve_handle: true, mode: 'preview' }, { principal: 'user:other' }),
      { code: 'HANDLE_ACCESS_DENIED' }
    );
  });
});

test('taskResult keeps ownerless resolved handle compatibility behavior', async () => {
  await withRuntime(async ({ runtime }) => {
    const task = {
      id: 'task_ownerless',
      capability_id: 'manual.capability',
      input: {},
      options: {},
      principal: null,
      resource: null,
      status: 'COMPLETED',
      events: [],
      policy_decisions: [],
      result: {
        handle: runtime.dataPut('ownerless task result')
      },
      error: null,
      created_at: new Date(0).toISOString(),
      updated_at: new Date(0).toISOString()
    };
    runtime.tasks.set(task.id, task);

    const result = runtime.taskResult(task.id, { resolve_handle: true, mode: 'preview' });

    assert.match(result.result.preview, /ownerless task result/);
  });
});

test('write capability requires approval by default', async () => {
  await withRuntime(async ({ runtime }) => {
    grantWriteFile(runtime, 'file:out.md');
    const task = await runtime.taskStart('filesystem.file.write', {
      path: 'out.md',
      content: 'blocked until approval'
    }, { principal: 'user:alex' });
    assert.equal(task.status, 'WAITING_APPROVAL');
    assert.ok(task.events.some((event) => event.type === 'APPROVAL_REQUIRED'));

    const approved = await runtime.taskApprove(task.task_id, { approved: true, by: 'test' });
    assert.equal(approved.status, 'COMPLETED');
  });
});

test('write capability can run with approval', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    grantWriteFile(runtime, 'file:generated/out.md');
    const task = await runtime.taskStart(
      'filesystem.file.write',
      { path: 'generated/out.md', content: 'hello from hcp' },
      { principal: 'user:alex', approval: { approved: true, by: 'test' } }
    );
    assert.equal(task.status, 'COMPLETED');
    assert.equal(await readFile(path.join(workspace, 'generated/out.md'), 'utf8'), 'hello from hcp');
  });
});

test('data.pipe moves a handle into write capability without exposing full payload', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    grantReadDoc(runtime);
    grantWriteFile(runtime, 'file:copied.md');
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });
    const pipeTask = await runtime.dataPipe(
      readTask.result.handle,
      'filesystem.file.write',
      {
        target_field: 'content',
        input: { path: 'copied.md' },
        transform: { max_bytes: 12 }
      },
      { principal: 'user:alex', approval: { approved: true, by: 'test' } }
    );

    assert.equal(pipeTask.status, 'COMPLETED');
    assert.equal(await readFile(path.join(workspace, 'copied.md'), 'utf8'), '# Hello HCP\n');
  });
});

test('dataPipe denies when target capability grant is missing', async () => {
  await withRuntime(async ({ runtime }) => {
    const handle = runtime.dataPut('# Hello HCP\n', {
      principal: 'user:alex',
      data_class: ['internal', 'file_content'],
      task_id: 'manual-source'
    });

    await assert.rejects(
      () =>
        runtime.dataPipe(
          handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'copied.md' }
          },
          { principal: 'user:alex', approval: { approved: true, by: 'test' } }
        ),
      (error) => error.code === 'POLICY_DENIED' && error.details.policy.reason === 'MISSING_GRANT'
    );
  });
});

test('dataPipe denies when target grant scope does not match', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:read'],
      resources: ['file:copied.md'],
      capabilities: ['filesystem.file.write']
    });
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    await assert.rejects(
      () =>
        runtime.dataPipe(
          readTask.result.handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'copied.md' }
          },
          { principal: 'user:alex', approval: { approved: true, by: 'test' } }
        ),
      (error) => error.code === 'POLICY_DENIED' && error.details.policy.reason === 'INSUFFICIENT_SCOPE'
    );
  });
});

test('dataPipe denies when target grant resource does not match', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    grantWriteFile(runtime, 'file:other.md');
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    await assert.rejects(
      () =>
        runtime.dataPipe(
          readTask.result.handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'copied.md' }
          },
          { principal: 'user:alex', approval: { approved: true, by: 'test' } }
        ),
      (error) => error.code === 'POLICY_DENIED' && error.details.policy.reason === 'RESOURCE_DENIED'
    );
  });
});

test('dataPipe denies when target grant capability does not match', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:write'],
      resources: ['file:copied.md'],
      capabilities: ['filesystem.file.read']
    });
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    await assert.rejects(
      () =>
        runtime.dataPipe(
          readTask.result.handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'copied.md' }
          },
          { principal: 'user:alex', approval: { approved: true, by: 'test' } }
        ),
      (error) => error.code === 'POLICY_DENIED' && error.details.policy.reason === 'CAPABILITY_DENIED'
    );
  });
});

test('dataPipe target write still requires approval after grant match', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    grantWriteFile(runtime, 'file:copied.md');
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    const pipeTask = await runtime.dataPipe(
      readTask.result.handle,
      'filesystem.file.write',
      {
        target_field: 'content',
        input: { path: 'copied.md' }
      },
      { principal: 'user:alex' }
    );

    assert.equal(pipeTask.status, 'WAITING_APPROVAL');
    assert.equal(pipeTask.policy.reason, 'write operation requires approval');
  });
});

test('dataPipe denies pii-class source when target capability does not accept pii', async () => {
  await withRuntime(async ({ runtime }) => {
    const handle = runtime.dataPut('email: alex@example.com', {
      principal: 'user:alex',
      data_class: ['pii'],
      task_id: 'manual-source'
    });
    grantWriteFile(runtime, 'file:copied.md');

    await assert.rejects(
      () =>
        runtime.dataPipe(
          handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'copied.md' }
          },
          { principal: 'user:alex', approval: { approved: true, by: 'test' } }
        ),
      (error) =>
        error.code === 'POLICY_DENIED' &&
        error.details.policy.reason === 'target capability does not accept pii-class data'
    );
  });
});

test('pipe-only handles keep sensitive content out of all caller projections', async () => {
  await withRuntime(async ({ runtime }) => {
    const handle = runtime.dataPut('email: alex@example.com', {
      principal: 'user:alex', data_class: ['pii'], release_policy: 'pipe_only'
    });
    const metadata = runtime.dataPeek(handle, { mode: 'metadata' }, { principal: 'user:alex' });
    assert.equal(metadata.metadata.release_policy, 'pipe_only');
    assert.equal(Object.hasOwn(metadata, 'digest'), false);
    for (const mode of ['preview', 'summary', 'full', 'unrecognized']) {
      assert.throws(() => runtime.dataPeek(handle, { mode }, { principal: 'user:alex' }), {
        code: 'DATA_RELEASE_RESTRICTED'
      });
    }
    assert.equal(runtime.auditEntries.filter(entry => entry.type === 'DATA_PEEK_DENIED' && entry.code === 'DATA_RELEASE_RESTRICTED').length, 4);
  });
});

test('dataPipe canonical target resource ignores caller supplied resource override', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    grantWriteFile(runtime, 'file:copied.md');
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    await assert.rejects(
      () =>
        runtime.dataPipe(
          readTask.result.handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'other.md' }
          },
          {
            principal: 'user:alex',
            resource: 'file:copied.md',
            approval: { approved: true, by: 'test' }
          }
        ),
      (error) => error.code === 'POLICY_DENIED' && error.details.policy.details.resource === 'file:other.md'
    );
  });
});

test('filesystem provider blocks path traversal', async () => {
  await withRuntime(async ({ runtime }) => {
    const task = await runtime.taskStart('filesystem.file.read', { path: '../secret.txt' });
    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.code, 'INVALID_INPUT');
  });
});

test('allows filesystem read with matching principal resource grant', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: './doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'COMPLETED');
    assert.equal(task.resource, 'file:doc.md');
    assert.equal(task.policy_decisions.at(-1).details.reason, 'GRANT_MATCHED');
  });
});

test('denies filesystem read without a matching grant', async () => {
  await withRuntime(async ({ runtime }) => {
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.code, 'POLICY_DENIED');
    assert.equal(task.error.message, 'MISSING_GRANT');
    assert.equal(task.policy_decisions[0].details.principal, 'user:alex');
    assert.equal(task.policy_decisions[0].details.resource, 'file:doc.md');
    assert.equal(task.policy_decisions[0].details.capability, 'filesystem.file.read');
    assert.equal(task.policy_decisions[0].details.allowed, false);
  });
});

test('denies required-scope capability when principal is missing', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'MISSING_PRINCIPAL');
  });
});

test('denies filesystem read when principal does not own the grant', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime, 'user:other');
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'MISSING_GRANT');
  });
});

test('denies filesystem read when grant scope does not match', async () => {
  await withRuntime(async ({ runtime }) => {
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:write'],
      resources: ['file:doc.md'],
      capabilities: ['filesystem.file.read']
    });

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'INSUFFICIENT_SCOPE');
  });
});

test('denies filesystem read when grant resource does not match', async () => {
  await withRuntime(async ({ runtime }) => {
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:read'],
      resources: ['file:other.md'],
      capabilities: ['filesystem.file.read']
    });

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'RESOURCE_DENIED');
  });
});

test('denies filesystem read when grant capability does not match', async () => {
  await withRuntime(async ({ runtime }) => {
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:read'],
      resources: ['file:doc.md'],
      capabilities: ['filesystem.file.list']
    });

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'CAPABILITY_DENIED');
  });
});

test('denies filesystem read after grant revoke', async () => {
  await withRuntime(async ({ runtime }) => {
    const grant = grantReadDoc(runtime);
    runtime.grantRevoke(grant.id);

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'GRANT_REVOKED');
    assert.deepEqual(task.policy_decisions[0].details.matched_grant_ids, [grant.id]);
  });
});

test('denies filesystem read after grant expiration', async () => {
  await withRuntime(async ({ runtime }) => {
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:read'],
      resources: ['file:doc.md'],
      capabilities: ['filesystem.file.read'],
      ttl_ms: -1
    });

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'GRANT_EXPIRED');
  });
});

test('rejects invalid grant expiration input', async () => {
  await withRuntime(async ({ runtime }) => {
    assert.throws(
      () =>
        runtime.grantCreate({
          principal: 'user:alex',
          scopes: ['filesystem:read'],
          resources: ['file:doc.md'],
          expires_at: 'not-a-date'
        }),
      { code: 'INVALID_INPUT' }
    );
  });
});

test('allows when one of multiple grants is valid', async () => {
  await withRuntime(async ({ runtime }) => {
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:write'],
      resources: ['file:doc.md'],
      capabilities: ['filesystem.file.read']
    });
    const validGrant = grantReadDoc(runtime);

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'COMPLETED');
    assert.deepEqual(task.policy_decisions.at(-1).details.matched_grant_ids, [validGrant.id]);
  });
});

test('allows valid grant when another matching grant is revoked', async () => {
  await withRuntime(async ({ runtime }) => {
    const revokedGrant = grantReadDoc(runtime);
    runtime.grantRevoke(revokedGrant.id);
    const validGrant = grantReadDoc(runtime);

    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'COMPLETED');
    assert.deepEqual(task.policy_decisions.at(-1).details.matched_grant_ids, [validGrant.id]);
  });
});

test('does not let approval bypass missing grant', async () => {
  await withRuntime(async ({ runtime }) => {
    const task = await runtime.taskStart(
      'filesystem.file.write',
      { path: 'out.md', content: 'approval alone is not enough' },
      { principal: 'user:alex', approval: { approved: true, by: 'test' } }
    );

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.message, 'MISSING_GRANT');
  });
});

test('requires both grant and approval for write capability', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    grantWriteFile(runtime, 'file:out.md');
    const waiting = await runtime.taskStart(
      'filesystem.file.write',
      { path: 'out.md', content: 'needs approval' },
      { principal: 'user:alex' }
    );
    assert.equal(waiting.status, 'WAITING_APPROVAL');

    const approved = await runtime.taskStart(
      'filesystem.file.write',
      { path: 'out.md', content: 'allowed' },
      { principal: 'user:alex', approval: { approved: true, by: 'test' } }
    );
    assert.equal(approved.status, 'COMPLETED');
    assert.equal(await readFile(path.join(workspace, 'out.md'), 'utf8'), 'allowed');
  });
});

test('canonical resource prevents caller supplied resource override', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    await writeFile(path.join(workspace, 'other.md'), 'Other document\n', 'utf8');
    grantReadDoc(runtime);

    const task = await runtime.taskStart(
      'filesystem.file.read',
      { path: 'other.md' },
      { principal: 'user:alex', resource: 'file:doc.md' }
    );

    assert.equal(task.status, 'FAILED');
    assert.equal(task.resource, 'file:other.md');
    assert.equal(task.error.message, 'RESOURCE_DENIED');
  });
});

test('windows separators are normalized before resource policy', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);

    const task = await runtime.taskStart('filesystem.file.read', { path: 'folder\\..\\doc.md' }, { principal: 'user:alex' });

    assert.equal(task.status, 'COMPLETED');
    assert.equal(task.resource, 'file:doc.md');
  });
});

test('absolute path outside workspace is rejected before policy allow', async () => {
  await withRuntime(async ({ runtime, workspace }) => {
    runtime.grantCreate({
      principal: 'user:alex',
      scopes: ['filesystem:read'],
      resources: ['file:outside.md'],
      capabilities: ['filesystem.file.read']
    });
    const outsidePath = path.resolve(workspace, '..', 'outside.md');

    const task = await runtime.taskStart('filesystem.file.read', { path: outsidePath }, { principal: 'user:alex' });

    assert.equal(task.status, 'FAILED');
    assert.equal(task.error.code, 'INVALID_INPUT');
  });
});

test('windows drive and UNC paths cannot bypass workspace root', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);

    for (const unsafePath of ['C:\\temp\\doc.md', '\\\\server\\share\\doc.md']) {
      const task = await runtime.taskStart('filesystem.file.read', { path: unsafePath }, { principal: 'user:alex' });

      assert.equal(task.status, 'FAILED');
      assert.equal(task.error.code, 'INVALID_INPUT');
    }
  });
});

test('denies dataPeek after handle revoke', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    runtime.dataRevoke(task.result.handle);

    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'preview' }, { principal: 'user:alex' }), {
      code: 'HANDLE_REVOKED'
    });
  });
});

test('handle metadata records principal capability resource and task id', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    const metadata = runtime.dataPeek(task.result.handle, { mode: 'metadata' }, { principal: 'user:alex' }).metadata;

    assert.equal(metadata.principal, 'user:alex');
    assert.equal(metadata.capability, 'filesystem.file.read');
    assert.equal(metadata.resource, 'file:doc.md');
    assert.equal(metadata.task_id, task.task_id);
  });
});

test('denies dataPeek after handle expiration', async () => {
  await withRuntime(async ({ runtime }) => {
    const handle = runtime.dataPut('short lived', { ttl_ms: -1 });

    assert.throws(() => runtime.dataPeek(handle, { mode: 'preview' }), {
      code: 'HANDLE_EXPIRED'
    });
  });
});

test('handle revoke wins when handle is both revoked and expired', async () => {
  await withRuntime(async ({ runtime }) => {
    const handle = runtime.dataPut('short lived', { ttl_ms: -1 });
    runtime.dataRevoke(handle);

    assert.throws(() => runtime.dataPeek(handle, { mode: 'preview' }), {
      code: 'HANDLE_REVOKED'
    });
  });
});

test('requires owning principal for full dataPeek', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'full' }), {
      code: 'MISSING_PRINCIPAL'
    });
    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'full' }, { principal: 'user:other' }), {
      code: 'HANDLE_ACCESS_DENIED'
    });
    assert.match(runtime.dataPeek(task.result.handle, { mode: 'full' }, { principal: 'user:alex' }).value, /Hello HCP/);
  });
});

test('requires owning principal for preview and summary dataPeek', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'preview' }), {
      code: 'MISSING_PRINCIPAL'
    });
    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'summary' }, { principal: 'user:other' }), {
      code: 'HANDLE_ACCESS_DENIED'
    });
    assert.match(runtime.dataPeek(task.result.handle, { mode: 'preview' }, { principal: 'user:alex' }).preview, /Hello HCP/);
    assert.match(runtime.dataPeek(task.result.handle, { mode: 'summary' }, { principal: 'user:alex' }).summary, /Hello HCP/);
  });
});

test('keeps ownerless handle projection access as compatibility behavior', async () => {
  await withRuntime(async ({ runtime }) => {
    const handle = runtime.dataPut('public compatibility value');

    assert.match(runtime.dataPeek(handle, { mode: 'preview' }).preview, /public compatibility/);
    assert.match(runtime.dataPeek(handle, { mode: 'summary' }).summary, /public compatibility/);
    assert.equal(runtime.dataPeek(handle, { mode: 'full' }).value, 'public compatibility value');
  });
});

test('dataPeek deny audit records mode and reason', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'summary' }), {
      code: 'MISSING_PRINCIPAL'
    });

    const trace = runtime.auditGetTrace(task.task_id);
    assert.ok(
      trace.audit_entries.some(
        (entry) =>
          entry.type === 'DATA_PEEK_DENIED' &&
          entry.mode === 'summary' &&
          entry.reason === 'MISSING_PRINCIPAL'
      )
    );
  });
});

test('denies dataPipe when principal does not own source handle', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime, 'user:alex');
    grantWriteFile(runtime, 'file:copied.md', 'user:other');
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });

    await assert.rejects(
      () =>
        runtime.dataPipe(
          readTask.result.handle,
          'filesystem.file.write',
          {
            target_field: 'content',
            input: { path: 'copied.md' }
          },
          { principal: 'user:other', approval: { approved: true, by: 'test' } }
        ),
      { code: 'HANDLE_ACCESS_DENIED' }
    );

    assert.ok(
      runtime.auditEntries.some(
        (entry) =>
          entry.type === 'DATA_PIPE_SOURCE_DENIED' &&
          entry.allowed === false &&
          entry.reason === 'HANDLE_ACCESS_DENIED' &&
          entry.source_capability === 'filesystem.file.read' &&
          entry.source_resource === 'file:doc.md'
      )
    );
  });
});

test('audit trace records allow and deny policy decisions', async () => {
  await withRuntime(async ({ runtime }) => {
    const grant = grantReadDoc(runtime);
    const allowed = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });
    const allowedTrace = runtime.auditGetTrace(allowed.task_id);
    assert.ok(
      allowedTrace.audit_entries.some(
        (entry) => entry.event?.type === 'POLICY_DECISION' && entry.event.payload.details.allowed === true
      )
    );

    runtime.grantRevoke(grant.id);
    const denied = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });
    const deniedTrace = runtime.auditGetTrace(denied.task_id);
    assert.ok(
      deniedTrace.audit_entries.some(
        (entry) =>
          entry.event?.type === 'POLICY_DECISION' &&
          entry.event.payload.details.allowed === false &&
          entry.event.payload.details.reason === 'GRANT_REVOKED'
      )
    );
  });
});

test('dataPipe audit trace links source handle target task and pipe policy', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    grantWriteFile(runtime, 'file:copied.md');
    const readTask = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });
    const pipeTask = await runtime.dataPipe(
      readTask.result.handle,
      'filesystem.file.write',
      {
        target_field: 'content',
        input: { path: 'copied.md' }
      },
      { principal: 'user:alex', approval: { approved: true, by: 'test' } }
    );

    const sourceTrace = runtime.auditGetTrace(readTask.task_id);
    const sourceCheckEntry = sourceTrace.audit_entries.find((entry) => entry.type === 'DATA_PIPE_SOURCE_CHECK');
    const policyEntry = sourceTrace.audit_entries.find((entry) => entry.type === 'DATA_PIPE_POLICY_DECISION');
    const startedEntry = sourceTrace.audit_entries.find((entry) => entry.type === 'DATA_PIPE_STARTED_TASK');
    assert.ok(sourceCheckEntry);
    assert.ok(policyEntry);
    assert.ok(startedEntry);
    assert.equal(sourceCheckEntry.allowed, true);
    assert.equal(sourceCheckEntry.reason, 'SOURCE_HANDLE_ALLOWED');
    assert.equal(policyEntry.source_capability, 'filesystem.file.read');
    assert.equal(policyEntry.source_resource, 'file:doc.md');
    assert.equal(policyEntry.target_capability, 'filesystem.file.write');
    assert.equal(policyEntry.target_resource, 'file:copied.md');
    assert.equal(policyEntry.allowed, true);
    assert.equal(policyEntry.reason, 'approved operation');
    assert.equal(policyEntry.pipe_id, startedEntry.pipe_id);
    assert.equal(startedEntry.target_task_id, pipeTask.task_id);
    assert.equal(startedEntry.task_id, pipeTask.task_id);

    const targetTrace = runtime.auditGetTrace(pipeTask.task_id);
    assert.ok(targetTrace.audit_entries.some((entry) => entry.type === 'DATA_PIPE_SOURCE_CHECK'));
    assert.ok(targetTrace.audit_entries.some((entry) => entry.type === 'DATA_PIPE_POLICY_DECISION'));
    assert.ok(targetTrace.audit_entries.some((entry) => entry.type === 'DATA_PIPE_STARTED_TASK'));
  });
});

test('grantList requires caller principal or admin access', async () => {
  await withRuntime(async ({ runtime }) => {
    const ownGrant = grantReadDoc(runtime, 'user:alex');
    const otherGrant = grantReadDoc(runtime, 'user:other');

    assert.throws(() => runtime.grantList(), { code: 'MISSING_PRINCIPAL_OR_ADMIN' });
    assert.throws(() => runtime.grantList({ principal: 'user:other' }, { principal: 'user:alex' }), {
      code: 'GRANT_LIST_ACCESS_DENIED'
    });

    const ownGrants = runtime.grantList({}, { principal: 'user:alex' });
    assert.deepEqual(ownGrants.map((grant) => grant.id), [ownGrant.id]);
    assert.ok(!ownGrants.some((grant) => grant.id === otherGrant.id));

    const allGrants = runtime.grantList({}, { admin: true });
    assert.equal(allGrants.length, 2);

    const filteredAdminGrants = runtime.grantList({ principal: 'user:alex' }, { admin: true });
    assert.deepEqual(filteredAdminGrants.map((grant) => grant.id), [ownGrant.id]);

    assert.ok(
      runtime.auditEntries.some(
        (entry) => entry.type === 'GRANT_LIST' && entry.allowed === false && entry.reason === 'MISSING_PRINCIPAL_OR_ADMIN'
      )
    );
    assert.ok(
      runtime.auditEntries.some(
        (entry) => entry.type === 'GRANT_LIST' && entry.allowed === false && entry.reason === 'GRANT_LIST_ACCESS_DENIED'
      )
    );
    assert.ok(
      runtime.auditEntries.some(
        (entry) =>
          entry.type === 'GRANT_LIST' &&
          entry.allowed === true &&
          entry.principal === 'user:alex' &&
          entry.returned_count === 1
      )
    );
  });
});

test('handle revoke denial is visible in audit trace', async () => {
  await withRuntime(async ({ runtime }) => {
    grantReadDoc(runtime);
    const task = await runtime.taskStart('filesystem.file.read', { path: 'doc.md' }, { principal: 'user:alex' });
    runtime.dataRevoke(task.result.handle);

    assert.throws(() => runtime.dataPeek(task.result.handle, { mode: 'preview' }, { principal: 'user:alex' }), {
      code: 'HANDLE_REVOKED'
    });

    const trace = runtime.auditGetTrace(task.task_id);
    assert.ok(trace.audit_entries.some((entry) => entry.type === 'DATA_REVOKED'));
    assert.ok(trace.audit_entries.some((entry) => entry.type === 'DATA_PEEK_DENIED' && entry.code === 'HANDLE_REVOKED'));
  });
});
