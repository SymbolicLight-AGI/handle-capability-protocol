import { createAuditEntries, withAuditAttempt } from './audit-context.js';
import { HcpError, InvalidInputError, NotFoundError } from './errors.js';
import {
  BILATERAL_FLOW_PROTOCOL,
  createFlowIdentity,
  flowDigest,
  publicKeyFingerprint,
  sameFlowValue,
  signFlowArtifact,
  verifyFlowArtifact
} from './flow-crypto.js';
import { makeId, nowIso } from './ids.js';
import { validateProviderManifest } from './provider-sdk.js';
import { BILATERAL_FLOW_CONSTRAINTS, EFFECT_RISK, TASK_STATES } from './core/constants.js';
import { digest } from './core/hash.js';
import { applyTransform } from './core/projection.js';
import {
  assertFlowActive,
  matchesGrantCapability,
  normalizeFlowMapping,
  principalCanDiscoverCapability,
  requireNonEmptyString,
  resolveFlowExpiresAt,
  resolveGrantExpiresAt,
  validateStringArray
} from './core/grants.js';
import { InMemoryDataVault } from './core/data-vault.js';
import { DefaultPolicyEngine } from './core/policy-engine.js';
import { explainMatch, matchesAuditFilter, matchesConstraints, maxRisk, tokenize } from './core/matching.js';

export { DefaultPolicyEngine, InMemoryDataVault };

export class HcpRuntime {
  constructor({
    policyEngine = new DefaultPolicyEngine(),
    dataVault,
    clock,
    flowDomain = {},
    flowStore = null,
    flowObserver = null,
    auditLogPath = null,
    onAuditEntry = null,
    retention = {}
  } = {}) {
    this.clock = clock;
    this.policyEngine = policyEngine;
    this.retention = {
      maxAuditEntries: Number.isInteger(retention?.maxAuditEntries) && retention.maxAuditEntries > 0
        ? retention.maxAuditEntries
        : null,
      maxCompletedTasks: Number.isInteger(retention?.maxCompletedTasks) && retention.maxCompletedTasks > 0
        ? retention.maxCompletedTasks
        : null,
      maxVaultObjects: Number.isInteger(retention?.maxVaultObjects) && retention.maxVaultObjects > 0
        ? retention.maxVaultObjects
        : null
    };
    this.dataVault = dataVault ?? new InMemoryDataVault({
      clock,
      maxObjects: this.retention.maxVaultObjects
    });
    this.flowIdentity = createFlowIdentity(flowDomain);
    this.flowStore = flowStore;
    this.flowObserver = flowObserver;
    this.auditLogPath = auditLogPath;
    this.onAuditEntry = onAuditEntry;
    this.flowPeers = new Map();
    this.flowReleaseProposals = new Map();
    this.flowReleasePermits = new Map();
    this.flowAcceptPermits = new Map();
    this.flowReceipts = new Map();
    this.providers = new Map();
    this.providerManifestRecords = new Map();
    this.capabilities = new Map();
    this.tasks = new Map();
    this.tasksByIdempotencyKey = new Map();
    this.taskEventWatchers = new Map();
    this.grants = new Map();
    this.workspaceRoots = new Map();
    this.approvalRequests = new Map();
    this.inputRequests = new Map();
    this.modelRequests = new Map();
    this.auditEntries = createAuditEntries({
      auditLogPath,
      onEntry: onAuditEntry,
      maxEntries: this.retention.maxAuditEntries
    });
  }

  pruneState({
    maxAuditEntries = this.retention.maxAuditEntries,
    maxCompletedTasks = this.retention.maxCompletedTasks,
    maxVaultObjects = this.retention.maxVaultObjects
  } = {}) {
    const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
    let evictedTasks = 0;
    if (Number.isInteger(maxCompletedTasks) && maxCompletedTasks > 0) {
      const terminalTaskIds = [];
      for (const [taskId, task] of this.tasks.entries()) {
        if (TERMINAL_STATUSES.has(task.status)) {
          terminalTaskIds.push(taskId);
        }
      }
      if (terminalTaskIds.length > maxCompletedTasks) {
        const toEvict = new Set(terminalTaskIds.slice(0, terminalTaskIds.length - maxCompletedTasks));
        for (const taskId of toEvict) {
          this.tasks.delete(taskId);
          this.taskEventWatchers.delete(taskId);
          evictedTasks += 1;
        }
        for (const [key, mappedTaskId] of this.tasksByIdempotencyKey.entries()) {
          if (toEvict.has(mappedTaskId)) {
            this.tasksByIdempotencyKey.delete(key);
          }
        }
      }
    }

    let evictedAuditEntries = 0;
    if (Number.isInteger(maxAuditEntries) && maxAuditEntries > 0 && this.auditEntries.length > maxAuditEntries) {
      evictedAuditEntries = this.auditEntries.length - maxAuditEntries;
      this.auditEntries.splice(0, evictedAuditEntries);
    }

    const vaultPrune = typeof this.dataVault.prune === 'function'
      ? this.dataVault.prune({ maxObjects: maxVaultObjects })
      : { scrubbed: 0, evicted: 0, remaining: this.dataVault.objects?.size ?? 0 };

    return {
      evicted_tasks: evictedTasks,
      remaining_tasks: this.tasks.size,
      evicted_audit_entries: evictedAuditEntries,
      remaining_audit_entries: this.auditEntries.length,
      vault: vaultPrune
    };
  }

  // Trusted embedding/storage API. These methods are not protocol endpoints.
  flowExportState() {
    const names = [
      'flowPeers',
      'flowReleaseProposals',
      'flowReleasePermits',
      'flowAcceptPermits',
      'flowReceipts',
      'grants',
      'tasks',
      'tasksByIdempotencyKey'
    ];
    const state = {
      version: 1,
      domain_id: this.flowIdentity.domain_id,
      key_fingerprint: this.flowIdentity.key_fingerprint
    };
    for (const name of names) state[name] = structuredClone([...this[name]]);
    state.data_objects = structuredClone([...this.dataVault.objects]);
    state.audit_entries = structuredClone([...this.auditEntries]);
    return state;
  }

  flowImportState(state) {
    if (
      !state ||
      state.version !== 1 ||
      state.domain_id !== this.flowIdentity.domain_id ||
      state.key_fingerprint !== this.flowIdentity.key_fingerprint
    ) {
      throw new InvalidInputError('stored flow state does not match runtime identity');
    }
    for (const name of [
      'flowPeers',
      'flowReleaseProposals',
      'flowReleasePermits',
      'flowAcceptPermits',
      'flowReceipts',
      'grants',
      'tasks',
      'tasksByIdempotencyKey'
    ]) {
      this[name] = new Map(structuredClone(state[name] ?? []));
    }
    this.dataVault.objects = new Map(structuredClone(state.data_objects ?? []));
    this.auditEntries = createAuditEntries({
      auditLogPath: this.auditLogPath,
      onEntry: this.onAuditEntry
    });
    Array.prototype.push.apply(this.auditEntries, structuredClone(state.audit_entries ?? []));
  }

  #flowAtomic(operation) {
    if (!this.flowStore) return operation();
    let failure;
    const result = this.flowStore.transaction(() => {
      const saved = this.flowStore.loadSnapshot('runtime');
      if (saved) this.flowImportState(saved);
      try {
        return operation();
      } catch (error) {
        failure = error;
        return null;
      } finally {
        this.flowStore.saveSnapshot('runtime', this.flowExportState());
      }
    });
    if (failure) throw failure;
    return result;
  }

  #flowRefresh() {
    const saved = this.flowStore?.loadSnapshot('runtime');
    if (saved) this.flowImportState(saved);
  }

  flowQueryReceipt(contractDigest) {
    this.#flowRefresh();
    const receipt = this.flowReceipts.get(contractDigest);
    return {
      contract_digest: contractDigest,
      receipt: structuredClone(receipt ?? null),
      status: receipt?.outcome ?? 'INDETERMINATE'
    };
  }

  // The trusted host may reconcile a lost response; this never invokes a Provider.
  flowRecoverReceipt(receipt) {
    return this.#flowAtomic(() => {
      this.#verifyPeerFlowArtifact(receipt, 'hcp.flow.receipt');
      const record = this.flowReleasePermits.get(receipt?.release_permit_id);
      if (
        !record ||
        receipt.issuer_domain !== record.contract.target.domain_id ||
        receipt.source_domain !== this.flowIdentity.domain_id ||
        receipt.target_domain !== record.contract.target.domain_id ||
        receipt.contract_digest !== record.contract_digest ||
        receipt.accept_permit_id !== record.permit.accept_permit_id ||
        receipt.challenge_digest !== record.challenge_digest ||
        receipt.authorization_digest !== record.authorization_digest ||
        receipt.target_resource !== record.contract.target.resource ||
        !['COMMITTED', 'DENIED', 'FAILED', 'INDETERMINATE'].includes(receipt.outcome) ||
        (receipt.outcome === 'COMMITTED' && !receipt.target_task_id)
      ) {
        throw this.#flowDenied(
          'FLOW_RECOVERY_DENIED',
          'FLOW_RECEIPT_MISMATCH',
          'recovered receipt is not bound to the source authorization',
          { contract_digest: receipt?.contract_digest, release_permit_id: receipt?.release_permit_id }
        );
      }
      const prior = this.flowReceipts.get(record.contract_digest);
      if (prior && prior.artifact_digest !== receipt.artifact_digest) {
        throw this.#flowDenied(
          'FLOW_RECOVERY_DENIED',
          'FLOW_RECEIPT_MISMATCH',
          'receipt recovery cannot replace an existing terminal receipt',
          { contract_digest: record.contract_digest }
        );
      }
      record.status =
        receipt.outcome === 'COMMITTED'
          ? 'CONSUMED'
          : receipt.outcome === 'INDETERMINATE'
            ? 'INDETERMINATE'
            : 'FAILED';
      record.receipt_digest = receipt.artifact_digest;
      record.updated_at = nowIso(this.clock);
      this.flowReceipts.set(record.contract_digest, structuredClone(receipt));
      this.auditEntries.push({
        type: 'FLOW_RECEIPT_RECOVERED',
        timestamp: record.updated_at,
        principal: record.contract.source.principal,
        contract_digest: record.contract_digest,
        release_permit_id: receipt.release_permit_id,
        accept_permit_id: receipt.accept_permit_id,
        source_domain: this.flowIdentity.domain_id,
        target_domain: receipt.target_domain,
        allowed: true,
        reason: 'AUTHENTICATED_TERMINAL_RECEIPT_RECONCILED'
      });
      return {
        contract_digest: record.contract_digest,
        receipt: structuredClone(receipt),
        status: receipt.outcome
      };
    });
  }

  flowRecoverPending() {
    return this.#flowAtomic(() => {
      let changed = 0;
      for (const records of [this.flowReleasePermits, this.flowAcceptPermits]) {
        for (const record of records.values()) {
          if (['RESERVED', 'AUTHORIZED', 'COMMITTING', 'EXECUTING'].includes(record.status)) {
            record.status = 'INDETERMINATE';
            record.updated_at = nowIso(this.clock);
            changed++;
            this.auditEntries.push({
              type: 'FLOW_RECOVERY_STOPPED',
              timestamp: record.updated_at,
              principal:
                record.contract.source.domain_id === this.flowIdentity.domain_id
                  ? record.contract.source.principal
                  : record.contract.target.principal,
              contract_digest: record.contract_digest,
              allowed: false,
              reason: 'CRASH_OUTCOME_UNKNOWN_NO_REEXECUTION'
            });
          }
        }
      }
      return { changed, status: 'INDETERMINATE' };
    });
  }

  flowDomainDescribe() {
    return {
      protocol: BILATERAL_FLOW_PROTOCOL,
      domain_id: this.flowIdentity.domain_id,
      public_key_pem: this.flowIdentity.public_key_pem,
      key_fingerprint: this.flowIdentity.key_fingerprint,
      capabilities: [
        'release.propose',
        'accept.issue',
        'release.issue',
        'permit.revoke',
        'direct-runtime-transfer',
        'signed-receipt'
      ]
    };
  }

  flowPeerTrust(descriptor = {}) {
    const domainId = requireNonEmptyString(descriptor.domain_id, 'flow peer domain_id');
    const publicKeyPem = requireNonEmptyString(descriptor.public_key_pem, 'flow peer public_key_pem');
    if (descriptor.protocol !== BILATERAL_FLOW_PROTOCOL) {
      throw new InvalidInputError('flow peer protocol is not compatible', {
        domain_id: domainId,
        expected_protocol: BILATERAL_FLOW_PROTOCOL,
        actual_protocol: descriptor.protocol
      });
    }
    if (domainId === this.flowIdentity.domain_id) {
      throw new InvalidInputError('flow peer must use a different domain_id', { domain_id: domainId });
    }
    const actualFingerprint = publicKeyFingerprint(publicKeyPem);
    if (descriptor.key_fingerprint && descriptor.key_fingerprint !== actualFingerprint) {
      throw new InvalidInputError('flow peer key fingerprint mismatch', {
        domain_id: domainId,
        expected: descriptor.key_fingerprint,
        actual: actualFingerprint
      });
    }
    const existing = this.flowPeers.get(domainId);
    if (existing && existing.key_fingerprint !== actualFingerprint) {
      throw new HcpError('flow peer key rotation requires explicit replacement', 'FLOW_PEER_KEY_MISMATCH', {
        domain_id: domainId,
        existing_fingerprint: existing.key_fingerprint,
        proposed_fingerprint: actualFingerprint
      });
    }
    const peer = {
      protocol: descriptor.protocol,
      domain_id: domainId,
      public_key_pem: publicKeyPem,
      key_fingerprint: actualFingerprint,
      trusted_at: nowIso(this.clock)
    };
    this.flowPeers.set(domainId, peer);
    this.auditEntries.push({
      type: 'FLOW_PEER_TRUSTED',
      timestamp: peer.trusted_at,
      domain_id: this.flowIdentity.domain_id,
      peer_domain: domainId,
      peer_key_fingerprint: actualFingerprint
    });
    return structuredClone(peer);
  }

  flowPeerList() {
    return [...this.flowPeers.values()].map((peer) => structuredClone(peer));
  }

  async registerProvider(provider) {
    const manifest = validateProviderManifest(await provider.manifest());
    const providerId = manifest.provider.id;
    this.providers.set(providerId, {
      provider,
      manifest,
      quarantined_at: null,
      quarantine_reason: null
    });

    for (const capability of manifest.capabilities) {
      if (this.capabilities.has(capability.id)) {
        throw new InvalidInputError(`Duplicate capability id: ${capability.id}`, {
          capability: capability.id,
          provider: providerId
        });
      }
      this.capabilities.set(capability.id, {
        capability,
        provider,
        providerId,
        providerMetadata: manifest.provider
      });
    }

    return {
      provider: manifest.provider,
      capabilities: manifest.capabilities.map((capability) => capability.id)
    };
  }

  providerRegister(manifest, options = {}) {
    const validated = validateProviderManifest(manifest);
    const providerId = validated.provider.id;
    const record = {
      provider_id: providerId,
      status: this.providers.has(providerId) ? 'ACTIVE_PROVIDER_MANIFEST_REGISTERED' : 'MANIFEST_REGISTERED',
      manifest: structuredClone(validated),
      manifest_digest: digest(validated),
      source: options.source ?? 'runtime.provider.register',
      executable: this.providers.has(providerId),
      created_at: nowIso(this.clock),
      updated_at: nowIso(this.clock)
    };
    this.providerManifestRecords.set(providerId, record);
    this.auditEntries.push({
      type: 'PROVIDER_REGISTERED',
      timestamp: record.created_at,
      provider_id: providerId,
      manifest_digest: record.manifest_digest,
      executable: record.executable,
      source: record.source
    });
    return structuredClone(record);
  }

  async providerReload(providerId) {
    const entry = this.providers.get(providerId);
    if (!entry) throw new NotFoundError(`Unknown executable provider: ${providerId}`, { providerId });
    if (typeof entry.provider.manifest !== 'function') {
      throw new InvalidInputError(`Provider cannot reload manifest: ${providerId}`, { providerId });
    }

    const previousCapabilityIds = entry.manifest.capabilities.map((capability) => capability.id).sort();
    const manifest = validateProviderManifest(await entry.provider.manifest());
    if (manifest.provider.id !== providerId) {
      throw new InvalidInputError('Reloaded provider manifest id changed', {
        providerId,
        manifest_provider_id: manifest.provider.id
      });
    }
    const nextCapabilityIds = manifest.capabilities.map((capability) => capability.id).sort();
    if (JSON.stringify(previousCapabilityIds) !== JSON.stringify(nextCapabilityIds)) {
      throw new InvalidInputError('Provider reload cannot change capability ids in this prototype', {
        providerId,
        previous_capabilities: previousCapabilityIds,
        next_capabilities: nextCapabilityIds
      });
    }

    entry.manifest = manifest;
    for (const capability of manifest.capabilities) {
      const capabilityEntry = this.capabilities.get(capability.id);
      if (capabilityEntry?.providerId === providerId) {
        capabilityEntry.capability = capability;
        capabilityEntry.providerMetadata = manifest.provider;
      }
    }

    const record = {
      provider_id: providerId,
      reloaded: true,
      manifest_digest: digest(manifest),
      capabilities: nextCapabilityIds,
      reloaded_at: nowIso(this.clock)
    };
    this.auditEntries.push({
      type: 'PROVIDER_RELOADED',
      timestamp: record.reloaded_at,
      provider_id: providerId,
      manifest_digest: record.manifest_digest,
      capabilities: nextCapabilityIds
    });
    return record;
  }

  async capSearch(query, constraints = {}, options = {}) {
    return withAuditAttempt(
      this,
      { method: 'cap.search', principal: options.principal ?? null, object: 'catalog' },
      () => this.#capSearchInAttempt(query, constraints, options)
    );
  }

  async #capSearchInAttempt(query, constraints = {}, options = {}) {
    const terms = tokenize(query);
    const candidates = [];
    const scopeDiscovery = options.scope_discovery === true || options.principal !== undefined;
    const discoveryPrincipal = options.principal ?? null;
    const grants = scopeDiscovery ? [...this.grants.values()] : [];
    const withheld = [];

    for (const entry of this.capabilities.values()) {
      const { capability, provider, providerId } = entry;
      if (!matchesConstraints(capability, constraints)) continue;
      if (
        scopeDiscovery &&
        !principalCanDiscoverCapability({
          principal: discoveryPrincipal,
          capability,
          grants,
          now: new Date(nowIso(this.clock))
        })
      ) {
        withheld.push(capability.id);
        continue;
      }

      const searchable = [
        capability.id,
        capability.title,
        capability.description,
        ...(capability.intents ?? [])
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

      let score = 0;
      for (const term of terms) {
        if (searchable.includes(term)) score += 2;
        if (capability.id.includes(term)) score += 2;
      }
      score -= EFFECT_RISK[capability.effects.kind] ?? 1;

      const providerEntry = this.providers.get(providerId);
      const health = typeof provider.health === 'function' ? await provider.health() : { status: 'unknown' };
      const quarantined = Boolean(providerEntry?.quarantined_at);
      if (health.status === 'ok' && !quarantined) score += 1;
      if (quarantined) score -= 100;

      candidates.push({ entry, score, health, quarantined });
    }

    candidates.sort((a, b) => b.score - a.score);
    if (withheld.length > 0) {
      this.auditEntries.push({
        type: 'CAPABILITY_DISCOVERY_SCOPED',
        operation: 'tools/list',
        object: 'catalog',
        decision: 'withhold',
        reason: 'CAPABILITY_DISCOVERY_SCOPED',
        timestamp: nowIso(this.clock),
        principal: discoveryPrincipal,
        visible: candidates.length,
        withheld: withheld.length,
        withheld_capabilities: [...withheld]
      });
    }
    const requestedLimit = constraints.tool_budget ?? constraints.limit ?? 7;
    const limit = Number.isInteger(requestedLimit) && requestedLimit >= 0 ? requestedLimit : 7;

    return candidates.slice(0, limit).map(({ entry, score, health, quarantined }) => ({
      capability: entry.capability.id,
      title: entry.capability.title,
      why: explainMatch(entry.capability, terms, score),
      risk: entry.capability.effects?.risk ?? 'low',
      effect: entry.capability.effects?.kind ?? 'read',
      auth_status: quarantined ? 'provider_quarantined' : health.status === 'ok' ? 'available' : 'provider_unhealthy',
      publisher_trust: entry.capability.attestation ? 'attested' : 'local_or_unattested',
      provider: entry.providerId
    }));
  }

  capDescribe(capabilityId, detailLevel = 'summary') {
    const entry = this.capabilities.get(capabilityId);
    if (!entry) throw new NotFoundError(`Unknown capability: ${capabilityId}`, { capabilityId });
    const capability = structuredClone(entry.capability);
    if (detailLevel === 'summary') {
      return {
        id: capability.id,
        version: capability.version,
        title: capability.title,
        description: capability.description,
        intents: capability.intents,
        input_schema: capability.input_schema,
        output_schema: capability.output_schema,
        effects: capability.effects,
        security: {
          required_scopes: capability.security.required_scopes,
          data_in: capability.security.data_in,
          data_out: capability.security.data_out,
          approval: capability.security.approval
        }
      };
    }
    return capability;
  }

  async resourceResolve(capabilityId, input = {}, options = {}) {
    const entry = this.capabilities.get(capabilityId);
    if (!entry) throw new NotFoundError(`Unknown capability: ${capabilityId}`, { capabilityId });
    const resource = await this.#resolveResource(entry, input, options);
    return {
      capability: capabilityId,
      provider: entry.providerId,
      resource,
      input: structuredClone(input)
    };
  }

  async inspectRuntime() {
    return {
      runtime: {
        name: 'hcp-runtime-prototype',
        version: '0.3.0',
        state: 'in_memory'
      },
      counts: {
        providers: this.providers.size,
        registered_provider_manifests: this.providerManifestRecords.size,
        capabilities: this.capabilities.size,
        tasks: this.tasks.size,
        grants: this.grants.size,
        workspace_roots: this.workspaceRoots.size,
        approval_requests: this.approvalRequests.size,
        input_requests: this.inputRequests.size,
        model_requests: this.modelRequests.size,
        audit_entries: this.auditEntries.length
      },
      providers: [...this.providers.entries()].map(([providerId, entry]) => ({
        id: providerId,
        title: entry.manifest.provider.title ?? providerId,
        version: entry.manifest.provider.version ?? null,
        quarantined: Boolean(entry.quarantined_at),
        capabilities: entry.manifest.capabilities.map((capability) => capability.id)
      })),
      registered_provider_manifests: [...this.providerManifestRecords.values()].map((record) => ({
        provider_id: record.provider_id,
        status: record.status,
        executable: record.executable,
        manifest_digest: record.manifest_digest,
        capabilities: record.manifest.capabilities.map((capability) => capability.id),
        updated_at: record.updated_at
      })),
      capabilities: [...this.capabilities.values()].map((entry) => ({
        id: entry.capability.id,
        title: entry.capability.title,
        provider: entry.providerId,
        effect: entry.capability.effects?.kind ?? null,
        risk: entry.capability.effects?.risk ?? null,
        required_scopes: entry.capability.security?.required_scopes ?? []
      }))
    };
  }

  async inspectProvider(providerId = null) {
    if (providerId && !this.providers.has(providerId) && this.providerManifestRecords.has(providerId)) {
      const record = this.providerManifestRecords.get(providerId);
      return {
        id: providerId,
        provider: structuredClone(record.manifest.provider),
        health: { status: 'manifest_only' },
        manifest_only: true,
        manifest_digest: record.manifest_digest,
        capabilities: record.manifest.capabilities.map((capability) => ({
          id: capability.id,
          title: capability.title,
          description: capability.description ?? null,
          effects: structuredClone(capability.effects),
          security: structuredClone(capability.security),
          input_schema: structuredClone(capability.input_schema),
          output_schema: structuredClone(capability.output_schema)
        }))
      };
    }
    const entries = providerId ? [[providerId, this.providers.get(providerId)]] : [...this.providers.entries()];
    if (providerId && !entries[0][1]) {
      throw new NotFoundError(`Unknown provider: ${providerId}`, { providerId });
    }

    const providers = [];
    for (const [id, entry] of entries) {
      const health = typeof entry.provider.health === 'function' ? await entry.provider.health() : { status: 'unknown' };
      providers.push({
        id,
        provider: structuredClone(entry.manifest.provider),
        health,
        quarantined: Boolean(entry.quarantined_at),
        quarantined_at: entry.quarantined_at,
        quarantine_reason: entry.quarantine_reason,
        capabilities: entry.manifest.capabilities.map((capability) => ({
          id: capability.id,
          title: capability.title,
          description: capability.description ?? null,
          effects: structuredClone(capability.effects),
          security: structuredClone(capability.security),
          input_schema: structuredClone(capability.input_schema),
          output_schema: structuredClone(capability.output_schema)
        }))
      });
    }

    return providerId ? providers[0] : { providers };
  }

  async providerHealth(providerId) {
    const entry = this.providers.get(providerId);
    if (!entry) throw new NotFoundError(`Unknown provider: ${providerId}`, { providerId });
    const health = typeof entry.provider.health === 'function' ? await entry.provider.health() : { status: 'unknown' };
    return {
      provider_id: providerId,
      health,
      quarantined: Boolean(entry.quarantined_at),
      quarantined_at: entry.quarantined_at,
      quarantine_reason: entry.quarantine_reason
    };
  }

  providerVerify(providerId) {
    const entry = this.providers.get(providerId);
    const manifestRecord = this.providerManifestRecords.get(providerId);
    if (!entry && !manifestRecord) throw new NotFoundError(`Unknown provider: ${providerId}`, { providerId });
    const manifest = validateProviderManifest(entry?.manifest ?? manifestRecord.manifest);
    return {
      provider_id: providerId,
      valid: true,
      manifest_digest: digest(manifest),
      executable: Boolean(entry),
      capabilities: manifest.capabilities.map((capability) => capability.id),
      security_profile: {
        max_risk: maxRisk(manifest.capabilities),
        approval_required: manifest.capabilities.some((capability) => capability.security?.approval?.default === 'required')
      },
      supported_transports: manifest.provider.supported_transports ?? []
    };
  }

  providerQuarantine(providerId, reason = 'quarantined') {
    const entry = this.providers.get(providerId);
    if (!entry) throw new NotFoundError(`Unknown provider: ${providerId}`, { providerId });
    entry.quarantined_at = nowIso(this.clock);
    entry.quarantine_reason = reason;
    this.auditEntries.push({
      type: 'PROVIDER_QUARANTINED',
      timestamp: entry.quarantined_at,
      provider_id: providerId,
      reason
    });
    return {
      provider_id: providerId,
      quarantined: true,
      quarantined_at: entry.quarantined_at,
      reason
    };
  }

  grantCreate(input = {}) {
    const principal = input.principal;
    const scopes = input.scopes ?? [];
    const resources = input.resources ?? [];
    const capabilities = input.capabilities ?? [];

    if (typeof principal !== 'string' || principal.length === 0) {
      throw new InvalidInputError('grant principal must be a non-empty string', { principal });
    }
    validateStringArray(scopes, 'scopes');
    validateStringArray(resources, 'resources');
    if (capabilities.length > 0) validateStringArray(capabilities, 'capabilities');

    const now = this.clock?.() ?? new Date();
    const grant = {
      id: input.id ?? makeId('grant'),
      principal,
      scopes: [...scopes],
      resources: [...resources],
      capabilities: [...capabilities],
      expires_at: resolveGrantExpiresAt(input, now),
      revoked_at: null,
      created_at: nowIso(this.clock)
    };

    this.grants.set(grant.id, grant);
    this.auditEntries.push({
      type: 'GRANT_CREATED',
      timestamp: nowIso(this.clock),
      grant: structuredClone(grant)
    });
    return structuredClone(grant);
  }

  grantRevoke(grantId, reason = 'revoked') {
    const grant = this.grants.get(grantId);
    if (!grant) throw new NotFoundError(`Unknown grant: ${grantId}`, { grantId });
    grant.revoked_at = nowIso(this.clock);
    grant.revoked_reason = reason;
    this.auditEntries.push({
      type: 'GRANT_REVOKED',
      timestamp: grant.revoked_at,
      grant_id: grantId,
      reason
    });
    return structuredClone(grant);
  }

  grantList(filter = {}, options = {}) {
    const principal = options.principal ?? null;
    const admin = options.admin === true;
    if (!admin && !principal) {
      const reason = 'MISSING_PRINCIPAL_OR_ADMIN';
      this.auditEntries.push({
        type: 'GRANT_LIST',
        timestamp: nowIso(this.clock),
        principal,
        admin,
        filter: structuredClone(filter),
        allowed: false,
        reason,
        count: 0,
        returned_count: 0
      });
      throw new HcpError('Grant list requires principal or admin', reason, {
        operation: 'grant.list'
      });
    }
    if (!admin && filter.principal && filter.principal !== principal) {
      const reason = 'GRANT_LIST_ACCESS_DENIED';
      this.auditEntries.push({
        type: 'GRANT_LIST',
        timestamp: nowIso(this.clock),
        principal,
        admin,
        filter: structuredClone(filter),
        allowed: false,
        reason,
        count: 0,
        returned_count: 0
      });
      throw new HcpError('Grant list access denied for principal', reason, {
        operation: 'grant.list',
        principal,
        requested_principal: filter.principal
      });
    }

    const effectiveFilter = admin ? filter : { ...filter, principal };
    const grants = this.#listGrants(effectiveFilter);
    this.auditEntries.push({
      type: 'GRANT_LIST',
      timestamp: nowIso(this.clock),
      principal,
      admin,
      filter: structuredClone(filter),
      allowed: true,
      reason: 'GRANT_LIST_ALLOWED',
      count: grants.length,
      returned_count: grants.length
    });
    return grants;
  }

  async taskStart(capabilityId, input = {}, options = {}) {
    return withAuditAttempt(
      this,
      { method: 'task.start', principal: options.principal ?? null, object: capabilityId },
      () => this.#taskStartInAttempt(capabilityId, input, options)
    );
  }

  async #taskStartInAttempt(capabilityId, input = {}, options = {}, internalFlowDigest = null) {
    const entry = this.capabilities.get(capabilityId);
    if (!entry) throw new NotFoundError(`Unknown capability: ${capabilityId}`, { capabilityId });

    const idempotencyKey = options.idempotency_key;
    const denyCached = (code, reason, message, resource = options.resource ?? null) => {
      this.auditEntries.push({
        type: 'TASK_IDEMPOTENCY_DENIED',
        timestamp: nowIso(this.clock),
        principal: options.principal ?? null,
        capability: capabilityId,
        resource,
        idempotency_key_digest: digest(String(idempotencyKey)),
        allowed: false,
        reason
      });
      throw new HcpError(message, code, { capability: capabilityId, reason });
    };
    if (idempotencyKey != null && typeof idempotencyKey !== 'string') {
      throw new InvalidInputError('task idempotency key must be a string');
    }
    if (
      idempotencyKey?.startsWith('bilateral-flow:') &&
      (internalFlowDigest === null || idempotencyKey !== `bilateral-flow:${internalFlowDigest}`)
    ) {
      denyCached(
        'IDEMPOTENCY_KEY_RESERVED',
        'PRIVATE_FLOW_NAMESPACE',
        'bilateral-flow task keys require the private flow entry point'
      );
    }
    const idempotencyContext = idempotencyKey
      ? structuredClone({ capability_id: capabilityId, input, options })
      : null;

    if (idempotencyKey && this.tasksByIdempotencyKey.has(idempotencyKey)) {
      const taskId = this.tasksByIdempotencyKey.get(idempotencyKey);
      const cached = this.#getTask(taskId);
      const cachedContext = cached.idempotency_context ?? {
        capability_id: cached.capability_id,
        input: cached.input,
        options: cached.options
      };
      if (!sameFlowValue(cachedContext, idempotencyContext)) {
        denyCached(
          'IDEMPOTENCY_KEY_CONFLICT',
          'REQUEST_CONTEXT_CHANGED',
          'task idempotency key belongs to a different request'
        );
      }
      if (cached.status === 'PENDING') {
        denyCached(
          'IDEMPOTENCY_IN_PROGRESS',
          'RESOURCE_NOT_RESOLVED',
          'the original task has not resolved its resource yet'
        );
      }
      if (this.providers.get(entry.providerId)?.quarantined_at) {
        denyCached('PROVIDER_QUARANTINED', 'PROVIDER_QUARANTINED', 'the cached task provider is quarantined');
      }
      const currentOptions = { ...options, resource: await this.#resolveResource(entry, input, { ...options }) };
      if (currentOptions.resource !== cached.resource) {
        denyCached(
          'IDEMPOTENCY_KEY_CONFLICT',
          'CANONICAL_RESOURCE_CHANGED',
          'the cached task resource differs from the current canonical resource',
          currentOptions.resource
        );
      }
      const currentPolicy = this.#decidePolicy(entry, input, currentOptions, { operation: 'invoke' });
      if (currentPolicy.decision !== 'allow') {
        denyCached(
          currentPolicy.decision === 'deny' ? 'POLICY_DENIED' : 'APPROVAL_REQUIRED',
          currentPolicy.reason,
          'current authorization does not permit returning the cached task',
          currentOptions.resource
        );
      }
      this.auditEntries.push({
        type: 'TASK_IDEMPOTENCY_REUSED',
        timestamp: nowIso(this.clock),
        principal: currentOptions.principal ?? null,
        capability: capabilityId,
        resource: currentOptions.resource,
        task_id: taskId,
        allowed: true,
        reason: 'SAME_REQUEST_CURRENTLY_AUTHORIZED'
      });
      return this.taskSnapshot(taskId);
    }

    const task = this.#createTask(capabilityId, input, options);
    if (idempotencyKey) {
      task.idempotency_context = idempotencyContext;
      this.tasksByIdempotencyKey.set(idempotencyKey, task.id);
    }

    this.#emit(task, 'TASK_ACCEPTED', { capability: capabilityId });

    const providerEntry = this.providers.get(entry.providerId);
    if (providerEntry?.quarantined_at) {
      task.status = 'FAILED';
      task.error = {
        code: 'PROVIDER_QUARANTINED',
        message: providerEntry.quarantine_reason ?? 'provider quarantined',
        details: {
          provider_id: entry.providerId,
          quarantined_at: providerEntry.quarantined_at
        }
      };
      this.#emit(task, 'TASK_FAILED', { error: task.error });
      return this.taskSnapshot(task.id);
    }

    const taskOptions = { ...options };
    try {
      taskOptions.resource = await this.#resolveResource(entry, input, taskOptions);
    } catch (error) {
      task.status = 'FAILED';
      task.error = {
        code: error.code ?? 'INVALID_INPUT',
        message: error.message,
        details: error.details ?? {}
      };
      this.#emit(task, 'TASK_FAILED', { error: task.error });
      return this.taskSnapshot(task.id);
    }

    task.options = structuredClone(taskOptions);
    task.principal = taskOptions.principal ?? null;
    task.resource = taskOptions.resource ?? null;
    this.#emit(task, 'RESOURCE_RESOLVED', {
      principal: task.principal,
      resource: task.resource
    });

    const policy = this.#decidePolicy(entry, input, taskOptions, { operation: 'invoke' });
    task.policy_decisions.push(policy);
    this.#emit(task, 'POLICY_DECISION', policy);

    if (policy.decision === 'deny') {
      task.status = 'FAILED';
      task.error = { code: 'POLICY_DENIED', message: policy.reason };
      this.#emit(task, 'TASK_FAILED', { error: task.error });
      return this.taskSnapshot(task.id);
    }

    if (policy.decision === 'ask_approval') {
      task.status = 'WAITING_APPROVAL';
      this.#emit(task, 'APPROVAL_REQUIRED', {
        reason: policy.reason,
        capability: capabilityId,
        effect: entry.capability.effects.kind
      });
      return this.taskSnapshot(task.id);
    }

    return this.#invokeTask(task, entry, input, taskOptions);
  }

  taskList(filter = {}, options = {}) {
    const principal = options.principal ?? null;
    const admin = options.admin === true;
    if (
      !admin &&
      Object.prototype.hasOwnProperty.call(filter, 'principal') &&
      filter.principal !== principal
    ) {
      throw new HcpError('task.list cannot enumerate another principal', 'TASK_LIST_DENIED', {
        principal,
        requested_principal: filter.principal
      });
    }

    let tasks = [...this.tasks.values()];
    if (admin) {
      if (Object.prototype.hasOwnProperty.call(filter, 'principal')) {
        tasks = tasks.filter((task) => task.principal === filter.principal);
      }
    } else {
      tasks = tasks.filter((task) => task.principal === principal);
    }

    if (filter.status) {
      tasks = tasks.filter((task) => task.status === filter.status);
    }
    if (filter.capability_id) {
      tasks = tasks.filter((task) => task.capability_id === filter.capability_id);
    }

    const snapshots = tasks.map((task) => this.taskSnapshot(task.id));
    this.auditEntries.push({
      type: 'TASK_LIST',
      timestamp: nowIso(this.clock),
      principal,
      admin,
      filter: structuredClone(filter),
      count: snapshots.length
    });
    return snapshots;
  }

  async taskApprove(taskId, approval = { approved: true }) {
    const task = this.#getTask(taskId);
    if (task.status !== 'WAITING_APPROVAL') {
      throw new InvalidInputError(`Task is not waiting for approval: ${taskId}`, {
        taskId,
        status: task.status
      });
    }
    const entry = this.capabilities.get(task.capability_id);
    const taskOptions = {
      ...task.options,
      approval: {
        ...task.options.approval,
        ...approval
      }
    };
    task.options = structuredClone(taskOptions);
    this.#emit(task, 'APPROVAL_GRANTED', { approval });
    const policy = this.#decidePolicy(entry, task.input, taskOptions, { operation: 'invoke' });
    task.policy_decisions.push(policy);
    this.#emit(task, 'POLICY_DECISION', policy);

    if (policy.decision === 'deny') {
      task.status = 'FAILED';
      task.error = { code: 'POLICY_DENIED', message: policy.reason };
      this.#emit(task, 'TASK_FAILED', { error: task.error });
      return this.taskSnapshot(task.id);
    }
    if (policy.decision === 'ask_approval') {
      task.status = 'WAITING_APPROVAL';
      this.#emit(task, 'APPROVAL_REQUIRED', {
        reason: policy.reason,
        capability: task.capability_id,
        effect: entry.capability.effects.kind
      });
      return this.taskSnapshot(task.id);
    }

    return this.#invokeTask(task, entry, task.input, task.options);
  }

  taskCancel(taskId, reason = 'cancelled') {
    const task = this.#getTask(taskId);
    if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(task.status)) {
      throw new HcpError(`Task cannot be cancelled: ${taskId}`, 'TASK_NOT_CANCELLABLE', {
        taskId,
        status: task.status
      });
    }

    task.status = 'CANCELLING';
    task.updated_at = nowIso(this.clock);
    this.#emit(task, 'TASK_CANCELLING', { reason });

    task.status = 'CANCELLED';
    task.error = { code: 'TASK_CANCELLED', message: reason };
    task.updated_at = nowIso(this.clock);
    this.#emit(task, 'TASK_CANCELLED', { reason });

    return this.taskSnapshot(task.id);
  }

  taskProgress(taskId, progress = {}) {
    const task = this.#getTask(taskId);
    if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(task.status)) {
      throw new HcpError(`Task cannot report progress: ${taskId}`, 'TASK_TERMINAL', {
        taskId,
        status: task.status
      });
    }
    const event = this.#emit(task, 'TASK_PROGRESS', {
      message: progress.message ?? null,
      completed: progress.completed ?? null,
      total: progress.total ?? null,
      unit: progress.unit ?? null
    });
    return event;
  }

  taskWatch(taskId, sinceEvent = 0) {
    const task = this.#getTask(taskId);
    return task.events.filter((event) => event.event > sinceEvent);
  }

  taskWatchWait(taskId, sinceEvent = 0, { wait_ms = 0 } = {}) {
    const existing = this.taskWatch(taskId, sinceEvent);
    if (existing.length > 0 || wait_ms <= 0) {
      return Promise.resolve(existing);
    }

    return new Promise((resolve) => {
      const watcher = {
        sinceEvent,
        resolve,
        timer: setTimeout(() => {
          this.#removeTaskEventWatcher(taskId, watcher);
          resolve([]);
        }, wait_ms)
      };

      const watchers = this.taskEventWatchers.get(taskId) ?? new Set();
      watchers.add(watcher);
      this.taskEventWatchers.set(taskId, watchers);
    });
  }

  taskResult(taskId, projection = {}, options = {}) {
    const task = this.#getTask(taskId);
    if (task.status !== 'COMPLETED') {
      return {
        task_id: task.id,
        status: task.status,
        error: task.error ?? null
      };
    }

    if (task.result?.handle && projection.resolve_handle) {
      return {
        task_id: task.id,
        status: task.status,
        result: this.dataPeek(task.result.handle, projection, {
          principal: options.principal ?? task.principal ?? undefined
        })
      };
    }

    return {
      task_id: task.id,
      status: task.status,
      result: task.result
    };
  }

  async policyExplain(capabilityId, input = {}, options = {}, { operation = 'invoke' } = {}) {
    const entry = this.capabilities.get(capabilityId);
    if (!entry) throw new NotFoundError(`Unknown capability: ${capabilityId}`, { capabilityId });

    const explainOptions = { ...options };
    explainOptions.resource = await this.#resolveResource(entry, input, explainOptions);
    const policy = this.#decidePolicy(entry, input, explainOptions, { operation });
    const requiredScopes = entry.capability.security?.required_scopes ?? [];
    return {
      principal: explainOptions.principal ?? null,
      capability: capabilityId,
      resource: explainOptions.resource ?? null,
      required_scopes: requiredScopes,
      matched_grant_ids: policy.details?.matched_grant_ids ?? [],
      approval: {
        required: policy.approval_required,
        present: explainOptions.approval?.approved === true
      },
      decision: policy.decision,
      reason: policy.reason,
      policy
    };
  }

  rootAdd(input = {}, options = {}) {
    const uri = input.uri;
    if (typeof uri !== 'string' || uri.length === 0) {
      throw new InvalidInputError('root uri must be a non-empty string', { uri });
    }
    const principal = input.principal ?? options.principal ?? null;
    if (!principal) {
      throw new HcpError('Workspace root requires principal', 'MISSING_PRINCIPAL', {
        operation: 'root.add'
      });
    }
    const root = {
      id: input.id ?? makeId('root'),
      uri,
      name: input.name ?? null,
      principal,
      resource: input.resource ?? null,
      scopes: Array.isArray(input.scopes) ? [...input.scopes] : [],
      metadata: structuredClone(input.metadata ?? {}),
      created_at: nowIso(this.clock)
    };
    this.workspaceRoots.set(root.id, root);
    this.auditEntries.push({
      type: 'ROOT_ADDED',
      timestamp: root.created_at,
      root_id: root.id,
      uri: root.uri,
      principal: root.principal,
      resource: root.resource,
      scopes: root.scopes
    });
    return structuredClone(root);
  }

  rootList(filter = {}, options = {}) {
    const principal = options.principal ?? null;
    const admin = options.admin === true;
    if (!admin && !principal) {
      throw new HcpError('Workspace root list requires principal or admin', 'MISSING_PRINCIPAL_OR_ADMIN', {
        operation: 'root.list'
      });
    }
    if (!admin && filter.principal && filter.principal !== principal) {
      throw new HcpError('Workspace root list access denied for principal', 'ROOT_LIST_ACCESS_DENIED', {
        operation: 'root.list',
        principal,
        requested_principal: filter.principal
      });
    }

    const effectiveFilter = admin ? filter : { ...filter, principal };
    const roots = [...this.workspaceRoots.values()]
      .filter((root) => !effectiveFilter.id || root.id === effectiveFilter.id)
      .filter((root) => !effectiveFilter.principal || root.principal === effectiveFilter.principal)
      .filter((root) => !effectiveFilter.uri || root.uri === effectiveFilter.uri)
      .filter((root) => !effectiveFilter.resource || root.resource === effectiveFilter.resource)
      .map((root) => structuredClone(root));

    this.auditEntries.push({
      type: 'ROOT_LIST',
      timestamp: nowIso(this.clock),
      principal,
      admin,
      filter: structuredClone(filter),
      allowed: true,
      returned_count: roots.length
    });
    return roots;
  }

  rootRemove(rootId, options = {}) {
    const root = this.workspaceRoots.get(rootId);
    if (!root) throw new NotFoundError(`Unknown workspace root: ${rootId}`, { rootId });
    const principal = options.principal ?? null;
    const admin = options.admin === true;
    if (!admin && root.principal !== principal) {
      throw new HcpError('Workspace root remove access denied for principal', 'ROOT_ACCESS_DENIED', {
        operation: 'root.remove',
        root_id: rootId,
        principal
      });
    }
    this.workspaceRoots.delete(rootId);
    const removedAt = nowIso(this.clock);
    this.auditEntries.push({
      type: 'ROOT_REMOVED',
      timestamp: removedAt,
      root_id: rootId,
      uri: root.uri,
      principal: root.principal,
      removed_by: principal,
      admin
    });
    return {
      id: rootId,
      removed: true,
      removed_at: removedAt
    };
  }

  approvalRequest(actionSummary, risk = 'medium', options = {}) {
    if (typeof actionSummary !== 'string' || actionSummary.length === 0) {
      throw new InvalidInputError('approval action_summary must be a non-empty string', { actionSummary });
    }
    const request = {
      id: makeId('approval'),
      type: 'approval',
      status: 'WAITING_APPROVAL',
      action_summary: actionSummary,
      risk,
      principal: options.principal ?? null,
      capability: options.capability ?? null,
      resource: options.resource ?? null,
      task_id: options.task_id ?? null,
      reason: options.reason ?? null,
      created_at: nowIso(this.clock),
      expires_at: options.ttl_ms ? new Date((this.clock?.() ?? new Date()).getTime() + options.ttl_ms).toISOString() : null
    };
    this.approvalRequests.set(request.id, request);
    this.auditEntries.push({
      type: 'APPROVAL_REQUESTED',
      timestamp: request.created_at,
      request_id: request.id,
      principal: request.principal,
      capability: request.capability,
      resource: request.resource,
      task_id: request.task_id,
      request: structuredClone(request)
    });
    return structuredClone(request);
  }

  inputRequest(schema, prompt, options = {}) {
    if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
      throw new InvalidInputError('input schema must be an object', { schema });
    }
    if (typeof prompt !== 'string' || prompt.length === 0) {
      throw new InvalidInputError('input prompt must be a non-empty string', { prompt });
    }
    const request = {
      id: makeId('input'),
      type: 'input',
      status: 'WAITING_INPUT',
      schema: structuredClone(schema),
      prompt,
      principal: options.principal ?? null,
      capability: options.capability ?? null,
      resource: options.resource ?? null,
      task_id: options.task_id ?? null,
      reason: options.reason ?? null,
      created_at: nowIso(this.clock),
      expires_at: options.ttl_ms ? new Date((this.clock?.() ?? new Date()).getTime() + options.ttl_ms).toISOString() : null
    };
    this.inputRequests.set(request.id, request);
    this.auditEntries.push({
      type: 'INPUT_REQUESTED',
      timestamp: request.created_at,
      request_id: request.id,
      principal: request.principal,
      capability: request.capability,
      resource: request.resource,
      task_id: request.task_id,
      request: structuredClone(request)
    });
    return structuredClone(request);
  }

  modelRequest(request = {}, options = {}) {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      throw new InvalidInputError('model request must be an object', { request });
    }
    const principal = options.principal ?? request.principal ?? null;
    if (!principal) {
      throw new HcpError('model.request requires principal', 'MISSING_PRINCIPAL', {
        operation: 'model.request'
      });
    }
    const origin = options.origin ?? request.origin ?? null;
    if (typeof origin !== 'string' || origin.length === 0) {
      throw new InvalidInputError('model.request requires a non-empty origin', { origin });
    }
    const hasMessages = Array.isArray(request.messages) && request.messages.length > 0;
    const hasPrompt = typeof request.prompt === 'string' && request.prompt.length > 0;
    if (!hasMessages && !hasPrompt) {
      throw new InvalidInputError('model.request requires messages or prompt', { request });
    }

    const createdAt = nowIso(this.clock);
    const record = {
      id: makeId('model'),
      type: 'model_request',
      status: 'WAITING_MODEL',
      principal,
      origin,
      capability: options.capability ?? request.capability ?? null,
      resource: options.resource ?? request.resource ?? null,
      task_id: options.task_id ?? request.task_id ?? null,
      reason: options.reason ?? request.reason ?? null,
      request: structuredClone(request),
      created_at: createdAt,
      expires_at: options.ttl_ms ? new Date((this.clock?.() ?? new Date()).getTime() + options.ttl_ms).toISOString() : null
    };
    this.modelRequests.set(record.id, record);
    this.auditEntries.push({
      type: 'MODEL_REQUESTED',
      timestamp: createdAt,
      request_id: record.id,
      principal: record.principal,
      origin: record.origin,
      capability: record.capability,
      resource: record.resource,
      task_id: record.task_id,
      request: structuredClone(record)
    });
    return structuredClone(record);
  }

  dataPut(value, metadata = {}) {
    const handle = this.dataVault.put(value, metadata);
    this.auditEntries.push({
      type: 'DATA_PUT',
      timestamp: nowIso(this.clock),
      handle,
      metadata
    });
    return handle;
  }

  dataPeek(handle, projection = {}, options = {}) {
    return withAuditAttempt(
      this,
      { method: 'data.peek', principal: options.principal ?? null, object: handle },
      () => this.#dataPeekInAttempt(handle, projection, options)
    );
  }

  #dataPeekInAttempt(handle, projection = {}, options = {}) {
    let record;
    const mode = projection.mode ?? 'preview';
    let effectiveProjection = projection;
    try {
      record = this.dataVault.get(handle);
      if (mode !== 'metadata') {
        this.#assertHandlePrincipal(record, options, `data.peek.${mode}`);
        if (record.metadata.release_policy === 'pipe_only') {
          throw new HcpError(
            'This handle can release its content only through an authorized data pipe',
            'DATA_RELEASE_RESTRICTED',
            { handle, operation: `data.peek.${mode}` }
          );
        }
        if (record.metadata.release_policy === 'redacted_only') {
          const requestedRedactions = Array.isArray(projection.redactions) ? projection.redactions : [];
          if (mode === 'full' && !requestedRedactions.includes('secret') && !requestedRedactions.includes('secrets')) {
            throw new HcpError(
              'This handle contains sensitive secrets and cannot be released in unredacted full mode',
              'DATA_RELEASE_RESTRICTED',
              { handle, operation: `data.peek.${mode}` }
            );
          }
          effectiveProjection = {
            ...projection,
            redactions: [...new Set([...requestedRedactions, 'secret'])]
          };
        }
      }
    } catch (error) {
      this.auditEntries.push({
        type: 'DATA_PEEK_DENIED',
        operation: 'data.peek',
        object: handle,
        decision: 'deny',
        timestamp: nowIso(this.clock),
        handle,
        projection,
        mode,
        principal: options.principal ?? null,
        code: error.code ?? 'HCP_ERROR',
        reason: error.code ?? 'HCP_ERROR',
        message: error.message
      });
      throw error;
    }
    const response = this.dataVault.peek(handle, effectiveProjection);
    this.auditEntries.push({
      type: 'DATA_PEEK',
      operation: 'data.peek',
      object: handle,
      decision: 'allow',
      reason: 'HANDLE_ACCESS',
      timestamp: nowIso(this.clock),
      handle,
      projection,
      principal: options.principal ?? null
    });
    return response;
  }

  dataRevoke(handle, reason = 'revoked') {
    const revoked = this.dataVault.revoke(handle, reason);
    this.auditEntries.push({
      type: 'DATA_REVOKED',
      timestamp: nowIso(this.clock),
      handle,
      reason
    });
    return revoked;
  }

  dataDescribe(handle, options = {}) {
    let description;
    try {
      description = this.dataVault.peek(handle, { mode: 'metadata' });
    } catch (error) {
      this.auditEntries.push({
        type: 'DATA_DESCRIBE_DENIED',
        timestamp: nowIso(this.clock),
        handle,
        principal: options.principal ?? null,
        code: error.code ?? 'HCP_ERROR',
        reason: error.code ?? 'HCP_ERROR',
        message: error.message
      });
      throw error;
    }

    this.auditEntries.push({
      type: 'DATA_DESCRIBE',
      timestamp: nowIso(this.clock),
      handle,
      principal: options.principal ?? null
    });
    return description;
  }

  async dataPipe(sourceHandle, targetCapabilityId, mapping = {}, options = {}) {
    return withAuditAttempt(
      this,
      { method: 'data.pipe', principal: options.principal ?? null, object: sourceHandle },
      () => this.#dataPipeInAttempt(sourceHandle, targetCapabilityId, mapping, options)
    );
  }

  async #dataPipeInAttempt(sourceHandle, targetCapabilityId, mapping = {}, options = {}) {
    let sourceRecord;
    const pipeId = makeId('pipe');
    const entry = this.capabilities.get(targetCapabilityId);
    if (!entry) {
      this.auditEntries.push({
        type: 'DATA_PIPE_POLICY_DECISION',
        timestamp: nowIso(this.clock),
        pipe_id: pipeId,
        principal: options.principal ?? null,
        source_handle: sourceHandle,
        source_task_id: null,
        source_capability: null,
        source_resource: null,
        target_capability: targetCapabilityId,
        target_resource: null,
        target_task_id: null,
        allowed: false,
        reason: 'TARGET_CAPABILITY_NOT_FOUND'
      });
      throw new NotFoundError(`Unknown capability: ${targetCapabilityId}`, { targetCapabilityId });
    }
    const sourceAuditDetails = () => ({
      pipe_id: pipeId,
      principal: options.principal ?? null,
      source_handle: sourceHandle,
      source_task_id: sourceRecord?.metadata?.task_id ?? sourceRecord?.metadata?.owner_task_id ?? null,
      source_capability: sourceRecord?.metadata?.capability ?? sourceRecord?.metadata?.source ?? null,
      source_resource: sourceRecord?.metadata?.resource ?? null,
      target_capability: targetCapabilityId
    });
    try {
      sourceRecord = this.dataVault.get(sourceHandle);
      this.#assertHandlePrincipal(sourceRecord, options, 'data.pipe');
    } catch (error) {
      this.auditEntries.push({
        type: 'DATA_PIPE_SOURCE_DENIED',
        timestamp: nowIso(this.clock),
        ...sourceAuditDetails(),
        target_resource: null,
        target_task_id: null,
        allowed: false,
        reason: error.code ?? 'HCP_ERROR',
        code: error.code ?? 'HCP_ERROR',
        message: error.message
      });
      throw error;
    }

    this.auditEntries.push({
      type: 'DATA_PIPE_SOURCE_CHECK',
      timestamp: nowIso(this.clock),
      ...sourceAuditDetails(),
      target_resource: null,
      target_task_id: null,
      allowed: true,
      reason: 'SOURCE_HANDLE_ALLOWED'
    });

    const transformed = applyTransform(sourceRecord.value, mapping.transform ?? {});
    const targetField = mapping.target_field ?? 'body';
    const targetInput = {
      ...(mapping.input ?? {}),
      [targetField]: transformed
    };
    let targetResource;
    try {
      targetResource = await this.#resolveResource(entry, targetInput, options);
    } catch (error) {
      this.auditEntries.push({
        type: 'DATA_PIPE_POLICY_DECISION',
        timestamp: nowIso(this.clock),
        ...sourceAuditDetails(),
        target_resource: null,
        target_task_id: null,
        allowed: false,
        reason: error.code ?? 'HCP_ERROR',
        code: error.code ?? 'HCP_ERROR',
        message: error.message
      });
      throw error;
    }
    const pipeOptions = {
      ...options,
      resource: targetResource
    };

    const policy = this.#decidePolicy(entry, targetInput, pipeOptions, {
      operation: 'data.pipe',
      sourceHandleRecord: sourceRecord
    });

    this.auditEntries.push({
      type: 'DATA_PIPE_POLICY_DECISION',
      timestamp: nowIso(this.clock),
      ...sourceAuditDetails(),
      resource: pipeOptions.resource ?? null,
      target_resource: pipeOptions.resource ?? null,
      target_task_id: null,
      principal: pipeOptions.principal ?? null,
      allowed: policy.decision === 'allow',
      reason: policy.reason,
      decision: policy
    });

    if (policy.decision === 'deny') {
      throw new HcpError(`Data pipe denied: ${policy.reason}`, 'POLICY_DENIED', { policy });
    }
    if (policy.decision === 'ask_approval') {
      return {
        status: 'WAITING_APPROVAL',
        policy,
        pipe_id: pipeId,
        source_handle: sourceHandle,
        target_capability: targetCapabilityId
      };
    }

    const task = await this.taskStart(targetCapabilityId, targetInput, {
      ...pipeOptions,
      pipe_id: pipeId,
      source_handle: sourceHandle,
      invoked_by: 'data.pipe'
    });

    this.auditEntries.push({
      type: 'DATA_PIPE_STARTED_TASK',
      timestamp: nowIso(this.clock),
      ...sourceAuditDetails(),
      resource: pipeOptions.resource ?? null,
      target_resource: pipeOptions.resource ?? null,
      principal: pipeOptions.principal ?? null,
      target_task_id: task.task_id,
      task_id: task.task_id,
      allowed: true,
      reason: 'TARGET_TASK_STARTED'
    });

    return task;
  }

  flowReleasePropose(sourceHandle, request = {}, options = {}) {
    return this.#flowAtomic(() => this.#flowReleasePropose(sourceHandle, request, options));
  }

  #flowReleasePropose(sourceHandle, request = {}, options = {}) {
    const now = this.clock?.() ?? new Date();
    const targetDomain = requireNonEmptyString(request.target_domain, 'flow target_domain');
    const targetCapability = requireNonEmptyString(request.target_capability, 'flow target_capability');
    const purpose = requireNonEmptyString(request.purpose, 'flow purpose');
    this.#getTrustedFlowPeer(targetDomain);

    const sourceRecord = this.dataVault.get(sourceHandle);
    this.#assertHandlePrincipal(sourceRecord, options, 'flow.release.propose');
    const sourcePrincipal = requireNonEmptyString(
      sourceRecord.metadata.principal ?? options.principal,
      'flow source principal'
    );
    const targetPrincipal = requireNonEmptyString(
      request.target_principal ?? sourcePrincipal,
      'flow target principal'
    );
    const mapping = normalizeFlowMapping(request.mapping);
    const transform = request.transform ?? {};
    if (transform === null || typeof transform !== 'object' || Array.isArray(transform)) {
      throw new InvalidInputError('flow transform must be an object', { transform });
    }
    const expiresAt = resolveFlowExpiresAt(
      {
        expires_at: request.expires_at ?? options.expires_at,
        ttl_ms: request.ttl_ms ?? options.ttl_ms
      },
      now
    );
    const proposalId = makeId('flow_proposal');
    const unsignedProposal = {
      kind: 'hcp.flow.release-proposal',
      protocol: BILATERAL_FLOW_PROTOCOL,
      proposal_id: proposalId,
      issuer_domain: this.flowIdentity.domain_id,
      source: {
        domain_id: this.flowIdentity.domain_id,
        handle_commitment: flowDigest({
          domain_id: this.flowIdentity.domain_id,
          handle: sourceHandle,
          data_digest: sourceRecord.digest
        }),
        data_digest: sourceRecord.digest,
        principal: sourcePrincipal,
        data_class: structuredClone(sourceRecord.metadata.data_class ?? []),
        content_type: sourceRecord.metadata.content_type ?? null
      },
      target: {
        domain_id: targetDomain,
        capability: targetCapability,
        principal: targetPrincipal
      },
      purpose,
      mapping,
      transform: structuredClone(transform),
      issued_at: now.toISOString(),
      expires_at: expiresAt
    };
    const proposal = signFlowArtifact(this.flowIdentity, unsignedProposal);
    this.flowReleaseProposals.set(proposalId, {
      proposal,
      source_handle: sourceHandle,
      status: 'PROPOSED',
      created_at: proposal.issued_at,
      updated_at: proposal.issued_at
    });
    this.auditEntries.push({
      type: 'FLOW_RELEASE_PROPOSED',
      timestamp: proposal.issued_at,
      proposal_id: proposalId,
      proposal_digest: proposal.artifact_digest,
      source_domain: this.flowIdentity.domain_id,
      target_domain: targetDomain,
      principal: sourcePrincipal,
      source_handle: sourceHandle,
      source_handle_commitment: proposal.source.handle_commitment,
      target_capability: targetCapability,
      purpose,
      allowed: true,
      reason: 'FLOW_RELEASE_PROPOSED'
    });
    return structuredClone(proposal);
  }

  async flowAcceptIssue(proposal, options = {}) {
    const now = this.clock?.() ?? new Date();
    this.#verifyPeerFlowArtifact(proposal, 'hcp.flow.release-proposal');
    this.#assertFlowArtifactActive(proposal.expires_at, {
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.artifact_digest,
      source_domain: proposal.source?.domain_id,
      target_domain: this.flowIdentity.domain_id
    });
    if (
      proposal.issuer_domain !== proposal.source?.domain_id ||
      proposal.source?.domain_id === this.flowIdentity.domain_id
    ) {
      throw this.#flowDenied(
        'FLOW_ACCEPT_DENIED',
        'FLOW_SOURCE_DOMAIN_MISMATCH',
        'flow proposal issuer does not match its source domain',
        {
          proposal_id: proposal.proposal_id,
          issuer_domain: proposal.issuer_domain,
          source_domain: proposal.source?.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    if (proposal.target?.domain_id !== this.flowIdentity.domain_id) {
      throw this.#flowDenied(
        'FLOW_ACCEPT_DENIED',
        'FLOW_TARGET_DOMAIN_MISMATCH',
        'flow proposal targets a different domain',
        {
          proposal_id: proposal.proposal_id,
          proposal_digest: proposal.artifact_digest,
          source_domain: proposal.source?.domain_id,
          expected: this.flowIdentity.domain_id,
          actual: proposal.target?.domain_id
        }
      );
    }

    requireNonEmptyString(proposal.source?.principal, 'flow source principal');
    const proposedTargetPrincipal = requireNonEmptyString(
      proposal.target?.principal,
      'flow proposed target principal'
    );
    const targetPrincipal = requireNonEmptyString(options.principal, 'flow target principal');
    if (proposedTargetPrincipal !== targetPrincipal) {
      throw this.#flowDenied(
        'FLOW_ACCEPT_DENIED',
        'FLOW_TARGET_PRINCIPAL_MISMATCH',
        'flow target principal does not match authoritative target context',
        {
          proposal_id: proposal.proposal_id,
          proposal_digest: proposal.artifact_digest,
          source_domain: proposal.source?.domain_id,
          target_domain: this.flowIdentity.domain_id,
          proposed_principal: proposedTargetPrincipal,
          authoritative_principal: targetPrincipal
        }
      );
    }
    const targetCapability = requireNonEmptyString(proposal.target.capability, 'flow target capability');
    const entry = this.capabilities.get(targetCapability);
    if (!entry) {
      throw this.#flowDenied(
        'FLOW_ACCEPT_DENIED',
        'NOT_FOUND',
        `Unknown capability: ${targetCapability}`,
        {
          proposal_id: proposal.proposal_id,
          proposal_digest: proposal.artifact_digest,
          source_domain: proposal.source?.domain_id,
          target_domain: this.flowIdentity.domain_id,
          target_capability: targetCapability
        }
      );
    }

    const mapping = normalizeFlowMapping(proposal.mapping);
    const targetInput = {
      ...mapping.input,
      [mapping.target_field]: ''
    };
    const targetResource = await this.#resolveResource(entry, targetInput, options);
    const acceptOptions = {
      principal: targetPrincipal,
      approval: options.approval ? structuredClone(options.approval) : undefined,
      dry_run: options.dry_run === true,
      resource: targetResource
    };
    const sourceHandleRecord = {
      metadata: {
        data_class: structuredClone(proposal.source?.data_class ?? [])
      }
    };
    const policy = this.#decidePolicy(entry, targetInput, acceptOptions, {
      operation: 'data.pipe',
      sourceHandleRecord
    });
    this.auditEntries.push({
      type: 'FLOW_ACCEPT_POLICY_DECISION',
      timestamp: now.toISOString(),
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.artifact_digest,
      source_domain: proposal.source?.domain_id ?? proposal.issuer_domain,
      target_domain: this.flowIdentity.domain_id,
      principal: targetPrincipal,
      target_capability: targetCapability,
      target_resource: targetResource,
      allowed: policy.decision === 'allow',
      reason: policy.reason,
      decision: policy
    });
    if (policy.decision !== 'allow') {
      throw new HcpError(`Bilateral flow acceptance denied: ${policy.reason}`, 'FLOW_ACCEPT_DENIED', {
        policy,
        proposal_id: proposal.proposal_id
      });
    }

    const targetExpiry = resolveFlowExpiresAt(
      {
        expires_at: options.expires_at,
        ttl_ms: options.ttl_ms
      },
      now
    );
    const expiresAt = new Date(
      Math.min(new Date(proposal.expires_at).getTime(), new Date(targetExpiry).getTime())
    ).toISOString();
    const contract = {
      kind: 'hcp.flow.contract',
      protocol: BILATERAL_FLOW_PROTOCOL,
      contract_id: makeId('flow_contract'),
      proposal_digest: proposal.artifact_digest,
      source: structuredClone(proposal.source),
      target: {
        domain_id: this.flowIdentity.domain_id,
        capability: targetCapability,
        principal: targetPrincipal,
        resource: targetResource
      },
      purpose: proposal.purpose,
      mapping,
      transform: structuredClone(proposal.transform ?? {}),
      constraints: structuredClone(BILATERAL_FLOW_CONSTRAINTS),
      issued_at: now.toISOString(),
      expires_at: expiresAt
    };
    const contractDigest = flowDigest(contract);
    const acceptPermit = signFlowArtifact(this.flowIdentity, {
      kind: 'hcp.flow.accept-permit',
      protocol: BILATERAL_FLOW_PROTOCOL,
      permit_id: makeId('flow_accept'),
      issuer_domain: this.flowIdentity.domain_id,
      contract_digest: contractDigest,
      proposal_digest: proposal.artifact_digest,
      issued_at: now.toISOString(),
      expires_at: expiresAt
    });
    this.#flowAtomic(() => {
      this.#assertFlowArtifactActive(expiresAt, { proposal_id: proposal.proposal_id });
      const currentPolicy = this.#decidePolicy(entry, targetInput, acceptOptions, {
        operation: 'data.pipe',
        sourceHandleRecord
      });
      if (currentPolicy.decision !== 'allow') {
        throw this.#flowDenied(
          'FLOW_ACCEPT_DENIED',
          currentPolicy.details?.reason ?? 'FLOW_ACCEPT_DENIED',
          'target authorization changed during acceptance',
          { principal: targetPrincipal, target_resource: targetResource }
        );
      }
      this.flowAcceptPermits.set(acceptPermit.permit_id, {
        permit: acceptPermit,
        contract: structuredClone(contract),
        contract_digest: contractDigest,
        status: 'ISSUED',
        execution_options: {
          principal: targetPrincipal,
          approval: options.approval ? structuredClone(options.approval) : undefined,
          dry_run: options.dry_run === true
        },
        policy,
        created_at: acceptPermit.issued_at,
        updated_at: acceptPermit.issued_at
      });
      this.auditEntries.push({
        type: 'FLOW_ACCEPT_ISSUED',
        timestamp: acceptPermit.issued_at,
        proposal_id: proposal.proposal_id,
        proposal_digest: proposal.artifact_digest,
        contract_id: contract.contract_id,
        contract_digest: contractDigest,
        accept_permit_id: acceptPermit.permit_id,
        source_domain: contract.source.domain_id,
        target_domain: contract.target.domain_id,
        principal: targetPrincipal,
        target_capability: targetCapability,
        target_resource: targetResource,
        purpose: contract.purpose,
        allowed: true,
        reason: 'FLOW_ACCEPT_ISSUED'
      });
    });
    return {
      contract: structuredClone(contract),
      contract_digest: contractDigest,
      accept_permit: structuredClone(acceptPermit)
    };
  }

  flowReleaseIssue(proposalId, acceptance, options = {}) {
    return this.#flowAtomic(() => this.#flowReleaseIssue(proposalId, acceptance, options));
  }

  #flowReleaseIssue(proposalId, acceptance, options = {}) {
    const now = this.clock?.() ?? new Date();
    const proposalRecord = this.flowReleaseProposals.get(proposalId);
    if (!proposalRecord) {
      throw new NotFoundError(`Unknown flow proposal: ${proposalId}`, { proposal_id: proposalId });
    }
    if (proposalRecord.status !== 'PROPOSED') {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_PROPOSAL_NOT_ACTIVE',
        'flow proposal is not available for release issuance',
        {
          proposal_id: proposalId,
          proposal_digest: proposalRecord.proposal.artifact_digest,
          status: proposalRecord.status,
          source_domain: this.flowIdentity.domain_id,
          target_domain: proposalRecord.proposal.target?.domain_id
        }
      );
    }
    const proposal = proposalRecord.proposal;
    this.#assertFlowArtifactActive(proposal.expires_at, {
      proposal_id: proposalId,
      proposal_digest: proposal.artifact_digest,
      source_domain: this.flowIdentity.domain_id,
      target_domain: proposal.target?.domain_id
    });
    const contract = acceptance?.contract;
    const acceptPermit = acceptance?.accept_permit;
    if (!contract || !acceptPermit) {
      throw new InvalidInputError('flow acceptance must include contract and accept_permit');
    }
    const contractDigest = flowDigest(contract);
    if (acceptance.contract_digest !== contractDigest || acceptPermit.contract_digest !== contractDigest) {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_CONTRACT_DIGEST_MISMATCH',
        'flow contract digest mismatch',
        {
          proposal_id: proposalId,
          proposal_digest: proposal.artifact_digest,
          expected: contractDigest,
          acceptance_digest: acceptance.contract_digest,
          permit_digest: acceptPermit.contract_digest
        }
      );
    }
    this.#verifyPeerFlowArtifact(acceptPermit, 'hcp.flow.accept-permit');
    this.#assertFlowArtifactActive(acceptPermit.expires_at, {
      proposal_id: proposalId,
      proposal_digest: proposal.artifact_digest,
      accept_permit_id: acceptPermit.permit_id,
      contract_digest: contractDigest,
      source_domain: this.flowIdentity.domain_id,
      target_domain: proposal.target?.domain_id
    });
    if (contract.kind !== 'hcp.flow.contract' || contract.protocol !== BILATERAL_FLOW_PROTOCOL) {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_CONTRACT_INVALID',
        'unsupported bilateral flow contract',
        {
          proposal_id: proposalId,
          kind: contract.kind,
          protocol: contract.protocol
        }
      );
    }
    if (
      contract.proposal_digest !== proposal.artifact_digest ||
      contract.source?.domain_id !== this.flowIdentity.domain_id ||
      contract.target?.domain_id !== proposal.target.domain_id ||
      contract.target?.capability !== proposal.target.capability ||
      contract.target?.principal !== proposal.target.principal ||
      !sameFlowValue(contract.source, proposal.source) ||
      !sameFlowValue(contract.mapping, proposal.mapping) ||
      !sameFlowValue(contract.transform, proposal.transform) ||
      !sameFlowValue(contract.constraints, BILATERAL_FLOW_CONSTRAINTS) ||
      contract.purpose !== proposal.purpose
    ) {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_CONTRACT_SUBSTITUTION',
        'flow contract changed the signed release proposal',
        {
          proposal_id: proposalId,
          proposal_digest: proposal.artifact_digest,
          contract_id: contract.contract_id,
          contract_digest: contractDigest
        }
      );
    }
    if (acceptPermit.issuer_domain !== contract.target.domain_id) {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_ACCEPT_ISSUER_MISMATCH',
        'flow accept permit issuer does not match target domain',
        {
          proposal_id: proposalId,
          contract_digest: contractDigest,
          accept_permit_id: acceptPermit.permit_id,
          issuer_domain: acceptPermit.issuer_domain,
          target_domain: contract.target.domain_id
        }
      );
    }
    if (
      acceptPermit.proposal_digest !== proposal.artifact_digest ||
      !acceptPermit.permit_id ||
      acceptPermit.expires_at !== contract.expires_at ||
      new Date(contract.expires_at).getTime() > new Date(proposal.expires_at).getTime()
    ) {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_ACCEPT_PERMIT_MISMATCH',
        'flow accept permit or contract lifetime does not match the release proposal',
        {
          proposal_id: proposalId,
          proposal_digest: proposal.artifact_digest,
          accept_permit_id: acceptPermit.permit_id,
          accept_proposal_digest: acceptPermit.proposal_digest,
          proposal_expires_at: proposal.expires_at,
          contract_expires_at: contract.expires_at,
          accept_expires_at: acceptPermit.expires_at
        }
      );
    }

    const sourceRecord = this.dataVault.get(proposalRecord.source_handle);
    const principalOptions = {
      principal: options.principal ?? proposal.source.principal
    };
    this.#assertHandlePrincipal(sourceRecord, principalOptions, 'flow.release.issue');
    const currentCommitment = flowDigest({
      domain_id: this.flowIdentity.domain_id,
      handle: proposalRecord.source_handle,
      data_digest: sourceRecord.digest
    });
    if (
      sourceRecord.digest !== proposal.source.data_digest ||
      currentCommitment !== proposal.source.handle_commitment
    ) {
      throw this.#flowDenied(
        'FLOW_RELEASE_DENIED',
        'FLOW_SOURCE_COMMITMENT_MISMATCH',
        'flow source handle no longer matches proposal commitment',
        {
          proposal_id: proposalId,
          proposal_digest: proposal.artifact_digest,
          contract_digest: contractDigest,
          source_domain: this.flowIdentity.domain_id,
          target_domain: contract.target.domain_id
        }
      );
    }

    const releasePermit = signFlowArtifact(this.flowIdentity, {
      kind: 'hcp.flow.release-permit',
      protocol: BILATERAL_FLOW_PROTOCOL,
      permit_id: makeId('flow_release'),
      issuer_domain: this.flowIdentity.domain_id,
      contract_digest: contractDigest,
      proposal_digest: proposal.artifact_digest,
      accept_permit_id: acceptPermit.permit_id,
      issued_at: now.toISOString(),
      expires_at: contract.expires_at
    });
    this.flowReleasePermits.set(releasePermit.permit_id, {
      permit: releasePermit,
      contract: structuredClone(contract),
      contract_digest: contractDigest,
      proposal_id: proposalId,
      source_handle: proposalRecord.source_handle,
      status: 'ISSUED',
      created_at: releasePermit.issued_at,
      updated_at: releasePermit.issued_at
    });
    proposalRecord.status = 'RELEASED';
    proposalRecord.updated_at = releasePermit.issued_at;
    proposalRecord.contract_digest = contractDigest;
    proposalRecord.release_permit_id = releasePermit.permit_id;
    this.auditEntries.push({
      type: 'FLOW_RELEASE_ISSUED',
      timestamp: releasePermit.issued_at,
      proposal_id: proposalId,
      proposal_digest: proposal.artifact_digest,
      contract_id: contract.contract_id,
      contract_digest: contractDigest,
      release_permit_id: releasePermit.permit_id,
      accept_permit_id: acceptPermit.permit_id,
      source_domain: contract.source.domain_id,
      target_domain: contract.target.domain_id,
      principal: proposal.source.principal,
      source_handle: proposalRecord.source_handle,
      source_handle_commitment: proposal.source.handle_commitment,
      target_capability: contract.target.capability,
      target_resource: contract.target.resource,
      purpose: contract.purpose,
      allowed: true,
      reason: 'FLOW_RELEASE_ISSUED'
    });
    return structuredClone(releasePermit);
  }

  flowPermitRevoke(permitId, reason = 'revoked') {
    return this.#flowAtomic(() => this.#flowPermitRevoke(permitId, reason));
  }

  #flowPermitRevoke(permitId, reason = 'revoked') {
    const now = nowIso(this.clock);
    const record = this.flowReleasePermits.get(permitId) ?? this.flowAcceptPermits.get(permitId);
    if (!record) {
      throw new NotFoundError(`Unknown bilateral flow permit: ${permitId}`, { permit_id: permitId });
    }
    if (['AUTHORIZED', 'EXECUTING', 'COMMITTED', 'CONSUMED', 'FAILED', 'INDETERMINATE'].includes(record.status)) {
      throw new HcpError('consumed flow permit cannot be revoked', 'FLOW_PERMIT_NOT_REVOCABLE', {
        permit_id: permitId,
        status: record.status
      });
    }
    record.status = 'REVOKED';
    record.revoked_reason = reason;
    record.updated_at = now;
    this.auditEntries.push({
      type: 'FLOW_PERMIT_REVOKED',
      timestamp: now,
      permit_id: permitId,
      permit_kind: record.permit.kind,
      contract_digest: record.contract_digest,
      domain_id: this.flowIdentity.domain_id,
      allowed: false,
      reason
    });
    return {
      permit_id: permitId,
      status: record.status,
      reason
    };
  }

  async flowTransfer(acceptance, releasePermit, targetRuntime) {
    this.#flowRefresh();
    const now = this.clock?.() ?? new Date();
    let releaseRecord = this.flowReleasePermits.get(releasePermit?.permit_id);
    if (!releaseRecord) {
      throw new NotFoundError(`Unknown flow release permit: ${releasePermit?.permit_id}`, {
        permit_id: releasePermit?.permit_id
      });
    }
    if (releaseRecord.status !== 'ISSUED') {
      const code = releaseRecord.status === 'REVOKED' ? 'FLOW_PERMIT_REVOKED' : 'FLOW_REPLAY_DENIED';
      throw this.#flowDenied(
        'FLOW_TRANSFER_DENIED',
        code,
        'flow release permit is not active',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: releaseRecord.contract_digest,
          release_permit_id: releasePermit.permit_id,
          permit_id: releasePermit.permit_id,
          status: releaseRecord.status,
          source_domain: this.flowIdentity.domain_id,
          target_domain: releaseRecord.contract.target.domain_id
        }
      );
    }
    this.#assertFlowArtifactActive(releasePermit.expires_at, {
      contract_id: releaseRecord.contract.contract_id,
      contract_digest: releaseRecord.contract_digest,
      release_permit_id: releasePermit.permit_id,
      source_domain: this.flowIdentity.domain_id,
      target_domain: releaseRecord.contract.target.domain_id
    });
    this.#verifyOwnFlowArtifact(releasePermit, 'hcp.flow.release-permit');
    if (!sameFlowValue(releaseRecord.permit, releasePermit)) {
      throw this.#flowDenied(
        'FLOW_TRANSFER_DENIED',
        'FLOW_RELEASE_PERMIT_MISMATCH',
        'flow release permit differs from issuer record',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: releaseRecord.contract_digest,
          release_permit_id: releasePermit.permit_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: releaseRecord.contract.target.domain_id
        }
      );
    }
    if (
      !targetRuntime ||
      typeof targetRuntime.flowDomainDescribe !== 'function' ||
      typeof targetRuntime.flowReceive !== 'function'
    ) {
      throw new InvalidInputError('flow transfer requires a direct target runtime channel');
    }
    const targetDescriptor = targetRuntime.flowDomainDescribe();
    const trustedTarget = this.#getTrustedFlowPeer(releaseRecord.contract.target.domain_id);
    if (
      targetDescriptor.domain_id !== trustedTarget.domain_id ||
      targetDescriptor.key_fingerprint !== trustedTarget.key_fingerprint ||
      targetDescriptor.protocol !== BILATERAL_FLOW_PROTOCOL
    ) {
      throw this.#flowDenied(
        'FLOW_TRANSFER_DENIED',
        'FLOW_TARGET_RUNTIME_MISMATCH',
        'direct target runtime does not match trusted flow peer',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: releaseRecord.contract_digest,
          release_permit_id: releasePermit.permit_id,
          expected_domain: trustedTarget.domain_id,
          actual_domain: targetDescriptor.domain_id,
          actual_protocol: targetDescriptor.protocol
        }
      );
    }
    const contractDigest = flowDigest(acceptance?.contract);
    if (
      contractDigest !== releaseRecord.contract_digest ||
      acceptance?.contract_digest !== contractDigest ||
      acceptance?.accept_permit?.contract_digest !== contractDigest ||
      !sameFlowValue(acceptance?.contract, releaseRecord.contract) ||
      acceptance?.accept_permit?.permit_id !== releasePermit.accept_permit_id
    ) {
      throw this.#flowDenied(
        'FLOW_TRANSFER_DENIED',
        'FLOW_CONTRACT_DIGEST_MISMATCH',
        'flow transfer contract digest mismatch',
        {
          contract_id: releaseRecord.contract.contract_id,
          expected: releaseRecord.contract_digest,
          actual: contractDigest,
          release_permit_id: releasePermit.permit_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: releaseRecord.contract.target.domain_id
        }
      );
    }
    this.#verifyPeerFlowArtifact(acceptance.accept_permit, 'hcp.flow.accept-permit');
    if (
      acceptance.accept_permit.issuer_domain !== releaseRecord.contract.target.domain_id ||
      acceptance.accept_permit.proposal_digest !== releasePermit.proposal_digest
    ) {
      throw this.#flowDenied(
        'FLOW_TRANSFER_DENIED',
        'FLOW_ACCEPT_PERMIT_MISMATCH',
        'flow transfer accept permit does not match release record',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptance.accept_permit.permit_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: releaseRecord.contract.target.domain_id
        }
      );
    }

    this.#flowAtomic(() => {
      releaseRecord = this.flowReleasePermits.get(releasePermit.permit_id);
      if (releaseRecord.status !== 'ISSUED') {
        throw this.#flowDenied(
          'FLOW_TRANSFER_DENIED',
          'FLOW_REPLAY_DENIED',
          'release permit has already been reserved',
          { release_permit_id: releasePermit.permit_id, contract_digest: contractDigest }
        );
      }
      releaseRecord.status = 'RESERVED';
      releaseRecord.updated_at = now.toISOString();
      this.auditEntries.push({
        type: 'FLOW_RELEASE_RESERVED',
        timestamp: releaseRecord.updated_at,
        contract_id: releaseRecord.contract.contract_id,
        contract_digest: contractDigest,
        release_permit_id: releasePermit.permit_id,
        accept_permit_id: acceptance.accept_permit.permit_id,
        source_domain: this.flowIdentity.domain_id,
        target_domain: targetDescriptor.domain_id,
        allowed: true,
        reason: 'DIRECT_RUNTIME_TRANSFER_RESERVED'
      });
    });
    try {
      await this.flowObserver?.('source_reserved', { contract_digest: contractDigest });
      const receipt = await targetRuntime.flowReceive(
        {
          contract: structuredClone(acceptance.contract),
          contract_digest: contractDigest,
          accept_permit: structuredClone(acceptance.accept_permit),
          release_permit: structuredClone(releasePermit)
        },
        { sourceRuntime: this }
      );
      this.#flowRefresh();
      releaseRecord = this.flowReleasePermits.get(releasePermit.permit_id);
      this.#verifyPeerFlowArtifact(receipt, 'hcp.flow.receipt');
      if (
        receipt.issuer_domain !== releaseRecord.contract.target.domain_id ||
        receipt.source_domain !== this.flowIdentity.domain_id ||
        receipt.target_domain !== releaseRecord.contract.target.domain_id ||
        receipt.contract_digest !== contractDigest ||
        receipt.release_permit_id !== releasePermit.permit_id ||
        receipt.accept_permit_id !== acceptance.accept_permit.permit_id ||
        receipt.challenge_digest !== releaseRecord.challenge_digest ||
        receipt.authorization_digest !== releaseRecord.authorization_digest ||
        receipt.target_resource !== releaseRecord.contract.target.resource ||
        !['COMMITTED', 'DENIED', 'FAILED', 'INDETERMINATE'].includes(receipt.outcome) ||
        (receipt.outcome === 'COMMITTED' && !receipt.target_task_id)
      ) {
        throw new HcpError('target receipt does not match bilateral flow contract', 'FLOW_RECEIPT_MISMATCH', {
          contract_digest: contractDigest,
          receipt
        });
      }
      this.#flowAtomic(() => {
        releaseRecord = this.flowReleasePermits.get(releasePermit.permit_id);
        releaseRecord.status =
          receipt.outcome === 'COMMITTED'
            ? 'CONSUMED'
            : receipt.outcome === 'INDETERMINATE'
              ? 'INDETERMINATE'
              : 'FAILED';
        releaseRecord.updated_at = nowIso(this.clock);
        releaseRecord.receipt_digest = receipt.artifact_digest;
        this.flowReceipts.set(contractDigest, structuredClone(receipt));
        this.auditEntries.push({
          type: 'FLOW_TRANSFER_COMPLETED',
          timestamp: releaseRecord.updated_at,
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptance.accept_permit.permit_id,
          receipt_digest: receipt.artifact_digest,
          source_domain: this.flowIdentity.domain_id,
          target_domain: targetDescriptor.domain_id,
          target_task_id: receipt.target_task_id,
          allowed: receipt.outcome === 'COMMITTED',
          reason: receipt.reason,
          outcome: receipt.outcome
        });
      });
      return structuredClone(receipt);
    } catch (error) {
      this.#flowAtomic(() => {
        releaseRecord = this.flowReleasePermits.get(releasePermit.permit_id);
        const transportFailure =
          error.transport_error === true ||
          [
            'ETIMEDOUT',
            'ECONNRESET',
            'ECONNREFUSED',
            'FLOW_CHANNEL_ERROR',
            'FLOW_CHANNEL_TIMEOUT',
            'FLOW_RECEIPT_MISMATCH',
            'FLOW_SIGNATURE_INVALID'
          ].includes(error.code);
        releaseRecord.status = transportFailure ? 'INDETERMINATE' : 'FAILED';
        releaseRecord.updated_at = nowIso(this.clock);
        this.auditEntries.push({
          type: 'FLOW_TRANSFER_FAILED',
          timestamp: releaseRecord.updated_at,
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptance.accept_permit.permit_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: targetDescriptor.domain_id,
          allowed: false,
          reason: error.code ?? 'FLOW_TRANSFER_FAILED',
          message: error.message
        });
      });
      throw error;
    }
  }

  flowCommitAuthorize(challenge) {
    return this.#flowAtomic(() => this.#flowCommitAuthorize(challenge));
  }

  #flowCommitAuthorize(challenge) {
    const now = this.clock?.() ?? new Date();
    this.#verifyPeerFlowArtifact(challenge, 'hcp.flow.commit-challenge');
    this.#assertFlowArtifactActive(challenge.expires_at, {
      contract_digest: challenge.contract_digest,
      release_permit_id: challenge.release_permit_id,
      accept_permit_id: challenge.accept_permit_id,
      challenge_id: challenge.challenge_id,
      source_domain: this.flowIdentity.domain_id,
      target_domain: challenge.issuer_domain
    });
    const releaseRecord = this.flowReleasePermits.get(challenge.release_permit_id);
    if (!releaseRecord) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'NOT_FOUND',
        `Unknown flow release permit: ${challenge.release_permit_id}`,
        {
          contract_digest: challenge.contract_digest,
          release_permit_id: challenge.release_permit_id,
          accept_permit_id: challenge.accept_permit_id,
          challenge_id: challenge.challenge_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: challenge.issuer_domain
        }
      );
    }
    if (releaseRecord.status !== 'RESERVED') {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_RELEASE_NOT_RESERVED',
        'flow release permit is not reserved for commit',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: releaseRecord.contract_digest,
          release_permit_id: challenge.release_permit_id,
          accept_permit_id: challenge.accept_permit_id,
          challenge_id: challenge.challenge_id,
          status: releaseRecord.status,
          source_domain: this.flowIdentity.domain_id,
          target_domain: challenge.issuer_domain
        }
      );
    }
    if (
      challenge.contract_digest !== releaseRecord.contract_digest ||
      challenge.issuer_domain !== releaseRecord.contract.target.domain_id ||
      challenge.source_domain !== this.flowIdentity.domain_id ||
      challenge.accept_permit_id !== releaseRecord.permit.accept_permit_id
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_COMMIT_CHALLENGE_MISMATCH',
        'flow commit challenge does not match release permit',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: releaseRecord.contract_digest,
          challenge_contract_digest: challenge.contract_digest,
          release_permit_id: challenge.release_permit_id,
          accept_permit_id: challenge.accept_permit_id,
          challenge_id: challenge.challenge_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: challenge.issuer_domain
        }
      );
    }
    this.#assertFlowArtifactActive(releaseRecord.permit.expires_at, {
      contract_id: releaseRecord.contract.contract_id,
      contract_digest: releaseRecord.contract_digest,
      release_permit_id: challenge.release_permit_id,
      accept_permit_id: challenge.accept_permit_id,
      challenge_id: challenge.challenge_id,
      source_domain: this.flowIdentity.domain_id,
      target_domain: challenge.issuer_domain
    });
    let sourceRecord;
    try {
      sourceRecord = this.dataVault.get(releaseRecord.source_handle);
      this.#assertHandlePrincipal(sourceRecord, { principal: releaseRecord.contract.source.principal }, 'flow.commit.authorize');
    } catch (error) {
      throw this.#flowDenied('FLOW_COMMIT_DENIED', error.code ?? 'FLOW_SOURCE_DENIED', error.message, {
        contract_digest: releaseRecord.contract_digest,
        source_handle: releaseRecord.source_handle,
        principal: releaseRecord.contract.source.principal,
        release_permit_id: challenge.release_permit_id
      });
    }
    const currentCommitment = flowDigest({
      domain_id: this.flowIdentity.domain_id,
      handle: releaseRecord.source_handle,
      data_digest: sourceRecord.digest
    });
    if (
      sourceRecord.digest !== releaseRecord.contract.source.data_digest ||
      currentCommitment !== releaseRecord.contract.source.handle_commitment
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_SOURCE_COMMITMENT_MISMATCH',
        'flow source changed after release issuance',
        {
          contract_id: releaseRecord.contract.contract_id,
          contract_digest: releaseRecord.contract_digest,
          release_permit_id: challenge.release_permit_id,
          accept_permit_id: challenge.accept_permit_id,
          challenge_id: challenge.challenge_id,
          source_domain: this.flowIdentity.domain_id,
          target_domain: challenge.issuer_domain
        }
      );
    }
    const authorization = signFlowArtifact(this.flowIdentity, {
      kind: 'hcp.flow.commit-authorization',
      protocol: BILATERAL_FLOW_PROTOCOL,
      authorization_id: makeId('flow_authorization'),
      issuer_domain: this.flowIdentity.domain_id,
      target_domain: challenge.issuer_domain,
      contract_digest: challenge.contract_digest,
      release_permit_id: challenge.release_permit_id,
      accept_permit_id: challenge.accept_permit_id,
      challenge_digest: challenge.artifact_digest,
      commit_nonce: challenge.commit_nonce,
      data_digest: sourceRecord.digest,
      issued_at: now.toISOString(),
      expires_at: new Date(
        Math.min(now.getTime() + 30_000, new Date(releaseRecord.permit.expires_at).getTime())
      ).toISOString()
    });
    releaseRecord.status = 'AUTHORIZED';
    releaseRecord.challenge_digest = challenge.artifact_digest;
    releaseRecord.authorization_digest = authorization.artifact_digest;
    releaseRecord.updated_at = authorization.issued_at;
    this.auditEntries.push({
      type: 'FLOW_COMMIT_AUTHORIZED',
      timestamp: authorization.issued_at,
      contract_id: releaseRecord.contract.contract_id,
      contract_digest: releaseRecord.contract_digest,
      release_permit_id: releaseRecord.permit.permit_id,
      accept_permit_id: challenge.accept_permit_id,
      authorization_id: authorization.authorization_id,
      challenge_digest: challenge.artifact_digest,
      source_domain: this.flowIdentity.domain_id,
      target_domain: challenge.issuer_domain,
      source_handle: releaseRecord.source_handle,
      allowed: true,
      reason: 'DIRECT_RUNTIME_COMMIT_AUTHORIZED'
    });
    return {
      authorization,
      payload: structuredClone(sourceRecord.value)
    };
  }

  async flowReceive(bundle, { sourceRuntime } = {}) {
    this.#flowRefresh();
    const now = this.clock?.() ?? new Date();
    if (
      !sourceRuntime ||
      typeof sourceRuntime.flowDomainDescribe !== 'function' ||
      typeof sourceRuntime.flowCommitAuthorize !== 'function'
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_SOURCE_RUNTIME_REQUIRED',
        'bilateral flow receive requires an authenticated source runtime channel',
        {
          contract_digest: bundle?.contract_digest,
          release_permit_id: bundle?.release_permit?.permit_id,
          accept_permit_id: bundle?.accept_permit?.permit_id,
          source_domain: bundle?.contract?.source?.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    const contract = bundle?.contract;
    const acceptPermit = bundle?.accept_permit;
    const releasePermit = bundle?.release_permit;
    if (!contract || !acceptPermit || !releasePermit) {
      throw new InvalidInputError('flow receive requires contract, accept_permit, and release_permit');
    }
    const contractDigest = flowDigest(contract);
    if (
      bundle.contract_digest !== contractDigest ||
      acceptPermit.contract_digest !== contractDigest ||
      releasePermit.contract_digest !== contractDigest
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_CONTRACT_DIGEST_MISMATCH',
        'flow receive contract digest mismatch',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          supplied_contract_digest: bundle.contract_digest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          source_domain: contract.source?.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    if (
      contract.target?.domain_id !== this.flowIdentity.domain_id ||
      acceptPermit.issuer_domain !== this.flowIdentity.domain_id
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_TARGET_DOMAIN_MISMATCH',
        'flow receive target domain mismatch',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          expected: this.flowIdentity.domain_id,
          contract_target: contract.target?.domain_id,
          accept_issuer: acceptPermit.issuer_domain,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          source_domain: contract.source?.domain_id
        }
      );
    }
    if (
      releasePermit.issuer_domain !== contract.source?.domain_id ||
      releasePermit.accept_permit_id !== acceptPermit.permit_id ||
      releasePermit.proposal_digest !== acceptPermit.proposal_digest
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_RELEASE_ISSUER_MISMATCH',
        'flow release permit is not linked to the contract source and target acceptance',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          release_issuer: releasePermit.issuer_domain,
          source_domain: contract.source?.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    const sourceDescriptor = sourceRuntime.flowDomainDescribe();
    const trustedSource = this.#getTrustedFlowPeer(contract.source?.domain_id);
    if (
      sourceDescriptor.domain_id !== trustedSource.domain_id ||
      sourceDescriptor.key_fingerprint !== trustedSource.key_fingerprint ||
      sourceDescriptor.protocol !== BILATERAL_FLOW_PROTOCOL
    ) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_SOURCE_RUNTIME_MISMATCH',
        'direct source runtime does not match trusted flow peer',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          expected_domain: trustedSource.domain_id,
          actual_domain: sourceDescriptor.domain_id,
          actual_protocol: sourceDescriptor.protocol,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    this.#verifyOwnFlowArtifact(acceptPermit, 'hcp.flow.accept-permit');
    this.#verifyPeerFlowArtifact(releasePermit, 'hcp.flow.release-permit');
    this.#assertFlowArtifactActive(contract.expires_at, {
      contract_id: contract.contract_id,
      contract_digest: contractDigest,
      release_permit_id: releasePermit.permit_id,
      accept_permit_id: acceptPermit.permit_id,
      source_domain: contract.source?.domain_id,
      target_domain: this.flowIdentity.domain_id
    });
    this.#assertFlowArtifactActive(acceptPermit.expires_at, {
      contract_id: contract.contract_id,
      contract_digest: contractDigest,
      accept_permit_id: acceptPermit.permit_id,
      source_domain: contract.source?.domain_id,
      target_domain: this.flowIdentity.domain_id
    });
    this.#assertFlowArtifactActive(releasePermit.expires_at, {
      contract_id: contract.contract_id,
      contract_digest: contractDigest,
      release_permit_id: releasePermit.permit_id,
      source_domain: contract.source?.domain_id,
      target_domain: this.flowIdentity.domain_id
    });

    let acceptRecord = this.flowAcceptPermits.get(acceptPermit.permit_id);
    if (!acceptRecord || !sameFlowValue(acceptRecord.permit, acceptPermit)) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_ACCEPT_PERMIT_MISMATCH',
        'flow accept permit is not authoritative for this runtime',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          source_domain: contract.source?.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    if (acceptRecord.status !== 'ISSUED') {
      const code = acceptRecord.status === 'REVOKED' ? 'FLOW_PERMIT_REVOKED' : 'FLOW_REPLAY_DENIED';
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        code,
        'flow accept permit is not active',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          permit_id: acceptPermit.permit_id,
          status: acceptRecord.status,
          source_domain: contract.source.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    if (!sameFlowValue(acceptRecord.contract, contract)) {
      throw this.#flowDenied(
        'FLOW_COMMIT_DENIED',
        'FLOW_CONTRACT_SUBSTITUTION',
        'flow contract differs from target issuer record',
        {
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          source_domain: contract.source?.domain_id,
          target_domain: this.flowIdentity.domain_id
        }
      );
    }
    const preflightEntry = this.capabilities.get(contract.target.capability);
    const preflightInput = {
      ...normalizeFlowMapping(contract.mapping).input,
      [contract.mapping.target_field]: ''
    };
    const preflightResource = await this.#resolveResource(preflightEntry, preflightInput, acceptRecord.execution_options);
    this.#flowAtomic(() => {
      acceptRecord = this.flowAcceptPermits.get(acceptPermit.permit_id);
      if (acceptRecord.status !== 'ISSUED') {
        throw this.#flowDenied(
          'FLOW_COMMIT_DENIED',
          acceptRecord.status === 'REVOKED' ? 'FLOW_PERMIT_REVOKED' : 'FLOW_REPLAY_DENIED',
          'target acceptance is no longer active',
          { contract_digest: contractDigest, accept_permit_id: acceptPermit.permit_id }
        );
      }
      this.#assertFlowArtifactActive(acceptPermit.expires_at, { contract_digest: contractDigest });
      if (preflightResource !== contract.target.resource) {
        throw this.#flowDenied(
          'FLOW_COMMIT_DENIED',
          'FLOW_TARGET_RESOURCE_CHANGED',
          'target resource changed before disclosure',
          { contract_digest: contractDigest, target_resource: preflightResource }
        );
      }
      const preflightPolicy = this.#decidePolicy(
        preflightEntry,
        preflightInput,
        { ...acceptRecord.execution_options, principal: contract.target.principal, resource: preflightResource },
        { operation: 'data.pipe', sourceHandleRecord: { metadata: { data_class: contract.source.data_class ?? [] } } }
      );
      if (preflightPolicy.decision !== 'allow') {
        throw this.#flowDenied(
          'FLOW_COMMIT_DENIED',
          preflightPolicy.details?.reason ?? 'FLOW_TARGET_POLICY_DENIED',
          preflightPolicy.reason,
          {
            contract_digest: contractDigest,
            principal: contract.target.principal,
            target_capability: contract.target.capability,
            target_resource: preflightResource,
            policy: preflightPolicy
          }
        );
      }
      acceptRecord.status = 'COMMITTING';
      acceptRecord.release_permit_id = releasePermit.permit_id;
      acceptRecord.updated_at = now.toISOString();
    });
    await this.flowObserver?.('target_reserved', { contract_digest: contractDigest });
    const challenge = signFlowArtifact(this.flowIdentity, {
      kind: 'hcp.flow.commit-challenge',
      protocol: BILATERAL_FLOW_PROTOCOL,
      challenge_id: makeId('flow_challenge'),
      issuer_domain: this.flowIdentity.domain_id,
      source_domain: contract.source.domain_id,
      contract_digest: contractDigest,
      release_permit_id: releasePermit.permit_id,
      accept_permit_id: acceptPermit.permit_id,
      commit_nonce: makeId('nonce'),
      issued_at: now.toISOString(),
      expires_at: new Date(Math.min(now.getTime() + 30_000, new Date(contract.expires_at).getTime())).toISOString()
    });
    this.auditEntries.push({
      type: 'FLOW_COMMIT_CHALLENGED',
      timestamp: challenge.issued_at,
      contract_id: contract.contract_id,
      contract_digest: contractDigest,
      release_permit_id: releasePermit.permit_id,
      accept_permit_id: acceptPermit.permit_id,
      challenge_id: challenge.challenge_id,
      source_domain: contract.source.domain_id,
      target_domain: this.flowIdentity.domain_id,
      allowed: true,
      reason: 'SOURCE_RUNTIME_REAUTHORIZATION_REQUIRED'
    });

    let authorizationResult;
    try {
      await this.flowObserver?.('challenge_ready', { contract_digest: contractDigest });
      authorizationResult = await sourceRuntime.flowCommitAuthorize(challenge);
      await this.flowObserver?.('payload_received', { contract_digest: contractDigest });
      this.#verifyPeerFlowArtifact(authorizationResult.authorization, 'hcp.flow.commit-authorization');
      const authorization = authorizationResult.authorization;
      if (
        authorization.issuer_domain !== contract.source.domain_id ||
        authorization.contract_digest !== contractDigest ||
        authorization.release_permit_id !== releasePermit.permit_id ||
        authorization.accept_permit_id !== acceptPermit.permit_id ||
        authorization.challenge_digest !== challenge.artifact_digest ||
        authorization.commit_nonce !== challenge.commit_nonce ||
        authorization.target_domain !== this.flowIdentity.domain_id ||
        authorization.data_digest !== contract.source.data_digest
      ) {
        throw new HcpError(
          'source commit authorization does not match target challenge',
          'FLOW_COMMIT_AUTHORIZATION_MISMATCH',
          { contract_digest: contractDigest }
        );
      }
      this.#assertFlowArtifactActive(authorization.expires_at, {
        contract_id: contract.contract_id,
        contract_digest: contractDigest,
        release_permit_id: releasePermit.permit_id,
        accept_permit_id: acceptPermit.permit_id,
        authorization_id: authorization.authorization_id,
        source_domain: contract.source.domain_id,
        target_domain: this.flowIdentity.domain_id
      });
      if (digest(authorizationResult.payload) !== contract.source.data_digest) {
        throw new HcpError(
          'direct runtime payload does not match source commitment',
          'FLOW_PAYLOAD_DIGEST_MISMATCH',
          { contract_digest: contractDigest }
        );
      }
    } catch (error) {
      this.#flowAtomic(() => {
        acceptRecord = this.flowAcceptPermits.get(acceptPermit.permit_id);
        acceptRecord.status = error.transport_error ? 'INDETERMINATE' : 'FAILED';
        acceptRecord.updated_at = nowIso(this.clock);
        this.auditEntries.push({
          type: 'FLOW_COMMIT_DENIED',
          timestamp: acceptRecord.updated_at,
          contract_id: contract.contract_id,
          contract_digest: contractDigest,
          release_permit_id: releasePermit.permit_id,
          accept_permit_id: acceptPermit.permit_id,
          source_domain: contract.source.domain_id,
          target_domain: this.flowIdentity.domain_id,
          allowed: false,
          reason: error.code ?? 'FLOW_COMMIT_AUTHORIZATION_FAILED',
          message: error.message
        });
      });
      throw error;
    }

    let task = null;
    let outcome;
    let reason;
    let policy = null;
    let executionError = null;
    let executionStarted = false;
    try {
      const mapping = normalizeFlowMapping(contract.mapping);
      const targetInput = {
        ...mapping.input,
        [mapping.target_field]: applyTransform(authorizationResult.payload, contract.transform ?? {})
      };
      const entry = this.capabilities.get(contract.target.capability);
      if (!entry) {
        throw new NotFoundError(`Unknown capability: ${contract.target.capability}`, {
          targetCapability: contract.target.capability
        });
      }
      const executionOptions = {
        ...structuredClone(acceptRecord.execution_options),
        principal: contract.target.principal,
        flow_contract_digest: contractDigest,
        idempotency_key: `bilateral-flow:${contractDigest}`
      };
      const currentResource = await this.#resolveResource(entry, targetInput, executionOptions);
      if (currentResource !== contract.target.resource) {
        throw new HcpError(
          'target canonical resource changed after flow acceptance',
          'FLOW_TARGET_RESOURCE_CHANGED',
          {
            accepted_resource: contract.target.resource,
            current_resource: currentResource
          }
        );
      }
      executionOptions.resource = currentResource;
      this.#flowAtomic(() => {
        acceptRecord = this.flowAcceptPermits.get(acceptPermit.permit_id);
        if (acceptRecord.status !== 'COMMITTING') {
          throw this.#flowDenied(
            'FLOW_COMMIT_DENIED',
            acceptRecord.status === 'REVOKED' ? 'FLOW_PERMIT_REVOKED' : 'FLOW_REPLAY_DENIED',
            'target acceptance changed while waiting for source',
            { contract_digest: contractDigest, accept_permit_id: acceptPermit.permit_id }
          );
        }
        this.#assertFlowArtifactActive(acceptPermit.expires_at, { contract_digest: contractDigest });
        this.#assertFlowArtifactActive(authorizationResult.authorization.expires_at, {
          contract_digest: contractDigest
        });
        executionOptions.approval = structuredClone(acceptRecord.execution_options.approval);
        policy = this.#decidePolicy(entry, targetInput, executionOptions, {
          operation: 'data.pipe',
          sourceHandleRecord: {
            metadata: {
              data_class: structuredClone(contract.source.data_class ?? [])
            }
          }
        });
        if (policy.decision !== 'allow') {
          outcome = 'DENIED';
          reason = policy.reason;
          acceptRecord.status = 'FAILED';
        } else {
          acceptRecord.status = 'EXECUTING';
          acceptRecord.updated_at = nowIso(this.clock);
          this.auditEntries.push({
            type: 'FLOW_EXECUTION_CLAIMED',
            timestamp: acceptRecord.updated_at,
            contract_digest: contractDigest,
            accept_permit_id: acceptPermit.permit_id,
            principal: contract.target.principal,
            target_capability: contract.target.capability,
            target_resource: currentResource,
            allowed: true,
            reason: 'TARGET_EXECUTION_AUTHORIZED'
          });
          executionStarted = true;
        }
      });
      if (executionStarted) {
        await this.flowObserver?.('execution_claimed', { contract_digest: contractDigest });
        task = await withAuditAttempt(
          this,
          { method: 'task.start', principal: executionOptions.principal, object: contract.target.capability },
          () => this.#taskStartInAttempt(contract.target.capability, targetInput, executionOptions, contractDigest)
        );
        outcome = task.status === 'COMPLETED' ? 'COMMITTED' : 'INDETERMINATE';
        reason = task.status === 'COMPLETED' ? 'TARGET_TASK_COMMITTED' : task.error?.code ?? task.status;
        acceptRecord.status = task.status === 'COMPLETED' ? 'COMMITTED' : 'INDETERMINATE';
      }
    } catch (error) {
      executionError = error;
      outcome = executionStarted ? 'INDETERMINATE' : 'DENIED';
      reason = error.code ?? 'FLOW_TARGET_EXECUTION_FAILED';
      acceptRecord.status = executionStarted ? 'INDETERMINATE' : 'FAILED';
    }
    acceptRecord.updated_at = nowIso(this.clock);
    const receipt = signFlowArtifact(this.flowIdentity, {
      kind: 'hcp.flow.receipt',
      protocol: BILATERAL_FLOW_PROTOCOL,
      receipt_id: makeId('flow_receipt'),
      issuer_domain: this.flowIdentity.domain_id,
      source_domain: contract.source.domain_id,
      target_domain: this.flowIdentity.domain_id,
      contract_digest: contractDigest,
      release_permit_id: releasePermit.permit_id,
      accept_permit_id: acceptPermit.permit_id,
      challenge_digest: challenge.artifact_digest,
      authorization_digest: authorizationResult.authorization.artifact_digest,
      outcome,
      reason,
      error_message: executionError?.message ?? null,
      target_task_id: task?.task_id ?? null,
      target_resource: contract.target.resource,
      issued_at: acceptRecord.updated_at
    });
    const executedTaskRecord = task ? structuredClone(this.tasks.get(task.task_id)) : null;
    this.#flowAtomic(() => {
      const finalRecord = this.flowAcceptPermits.get(acceptPermit.permit_id);
      finalRecord.status =
        outcome === 'COMMITTED' ? 'COMMITTED' : outcome === 'INDETERMINATE' ? 'INDETERMINATE' : 'FAILED';
      finalRecord.updated_at = receipt.issued_at;
      finalRecord.receipt_digest = receipt.artifact_digest;
      if (executedTaskRecord) {
        this.tasks.set(task.task_id, executedTaskRecord);
        this.tasksByIdempotencyKey.set(`bilateral-flow:${contractDigest}`, task.task_id);
      }
      this.flowReceipts.set(contractDigest, structuredClone(receipt));
      this.auditEntries.push({
        type: outcome === 'COMMITTED' ? 'FLOW_COMMITTED' : 'FLOW_COMMIT_DENIED',
        timestamp: receipt.issued_at,
        contract_id: contract.contract_id,
        contract_digest: contractDigest,
        release_permit_id: releasePermit.permit_id,
        accept_permit_id: acceptPermit.permit_id,
        receipt_digest: receipt.artifact_digest,
        challenge_digest: challenge.artifact_digest,
        authorization_digest: authorizationResult.authorization.artifact_digest,
        source_domain: contract.source.domain_id,
        target_domain: this.flowIdentity.domain_id,
        target_capability: contract.target.capability,
        target_resource: contract.target.resource,
        target_task_id: task?.task_id ?? null,
        principal: contract.target.principal,
        purpose: contract.purpose,
        allowed: outcome === 'COMMITTED',
        reason,
        outcome,
        decision: policy,
        message: executionError?.message ?? null
      });
    });
    await this.flowObserver?.('receipt_persisted', { contract_digest: contractDigest });
    return structuredClone(receipt);
  }

  flowGetTrace(contractDigest) {
    const proposals = [...this.flowReleaseProposals.values()]
      .filter((record) => record.contract_digest === contractDigest)
      .map((record) => ({
        proposal: structuredClone(record.proposal),
        status: record.status,
        updated_at: record.updated_at
      }));
    const releasePermits = [...this.flowReleasePermits.values()]
      .filter((record) => record.contract_digest === contractDigest)
      .map((record) => ({
        permit: structuredClone(record.permit),
        status: record.status,
        challenge_digest: record.challenge_digest ?? null,
        authorization_digest: record.authorization_digest ?? null,
        receipt_digest: record.receipt_digest ?? null,
        updated_at: record.updated_at
      }));
    const acceptPermits = [...this.flowAcceptPermits.values()]
      .filter((record) => record.contract_digest === contractDigest)
      .map((record) => ({
        permit: structuredClone(record.permit),
        status: record.status,
        receipt_digest: record.receipt_digest ?? null,
        updated_at: record.updated_at
      }));
    const proposalDigests = new Set(
      [
        ...proposals.map((record) => record.proposal.artifact_digest),
        ...releasePermits.map((record) => record.permit.proposal_digest),
        ...acceptPermits.map((record) => record.permit.proposal_digest)
      ].filter(Boolean)
    );
    const releasePermitIds = new Set(releasePermits.map((record) => record.permit.permit_id));
    const acceptPermitIds = new Set(acceptPermits.map((record) => record.permit.permit_id));
    return {
      protocol: BILATERAL_FLOW_PROTOCOL,
      domain_id: this.flowIdentity.domain_id,
      contract_digest: contractDigest,
      proposals,
      release_permits: releasePermits,
      accept_permits: acceptPermits,
      receipt: structuredClone(this.flowReceipts.get(contractDigest) ?? null),
      audit_entries: structuredClone(
        this.auditEntries.filter(
          (entry) =>
            entry.contract_digest === contractDigest ||
            proposalDigests.has(entry.proposal_digest) ||
            releasePermitIds.has(entry.release_permit_id) ||
            acceptPermitIds.has(entry.accept_permit_id) ||
            releasePermitIds.has(entry.permit_id) ||
            acceptPermitIds.has(entry.permit_id)
        )
      )
    };
  }

  auditGetTrace(taskId) {
    const task = this.#getTask(taskId);
    return {
      task_id: task.id,
      capability_id: task.capability_id,
      status: task.status,
      events: task.events,
      policy_decisions: task.policy_decisions,
      result: task.result ?? null,
      error: task.error ?? null,
      audit_entries: this.auditEntries.filter(
        (entry) =>
          entry.task_id === taskId ||
          entry.owner_task_id === taskId ||
          entry.pipe_id === task.options?.pipe_id ||
          entry.handle === task.result?.handle ||
          entry.source_handle === task.result?.handle
      )
    };
  }

  auditSearch(filter = {}) {
    const entries = this.auditEntries.filter((entry) => matchesAuditFilter(entry, filter));
    const offset = Number.isInteger(filter.offset) && filter.offset > 0 ? filter.offset : 0;
    const limit = Number.isInteger(filter.limit) && filter.limit >= 0 ? filter.limit : entries.length;
    return {
      entries: structuredClone(entries.slice(offset, offset + limit)),
      total: entries.length,
      offset,
      limit
    };
  }

  auditExport(filter = {}) {
    const result = this.auditSearch(filter);
    const exported = {
      format: 'json',
      exported_at: nowIso(this.clock),
      total: result.total,
      entries: result.entries
    };
    return {
      ...exported,
      digest: digest(exported)
    };
  }

  taskSnapshot(taskId) {
    const task = this.#getTask(taskId);
    return {
      task_id: task.id,
      capability_id: task.capability_id,
      status: task.status,
      events: task.events,
      result: task.result ?? null,
      error: task.error ?? null,
      policy_decisions: task.policy_decisions,
      principal: task.principal ?? null,
      resource: task.resource ?? null,
      created_at: task.created_at,
      updated_at: task.updated_at,
      ttl_ms: task.options?.mcp_task?.ttl ?? task.options?.ttl_ms ?? null
    };
  }

  #createTask(capabilityId, input, options) {
    const task = {
      id: makeId('task'),
      capability_id: capabilityId,
      input: structuredClone(input),
      options: structuredClone(options),
      principal: options.principal ?? null,
      resource: options.resource ?? null,
      status: 'PENDING',
      events: [],
      policy_decisions: [],
      result: null,
      error: null,
      created_at: nowIso(this.clock),
      updated_at: nowIso(this.clock)
    };
    this.tasks.set(task.id, task);
    return task;
  }

  async #invokeTask(task, entry, input, options) {
    task.status = 'RUNNING';
    task.updated_at = nowIso(this.clock);
    this.#emit(task, 'PROVIDER_STARTED', {
      provider: entry.providerId,
      capability: entry.capability.id
    });

    try {
      const result = await entry.provider.invoke({
        capability: entry.capability,
        input,
        options,
        runtime: this,
        task: this.taskSnapshot(task.id)
      });

      task.result = result ?? {};
      task.status = 'COMPLETED';
      task.updated_at = nowIso(this.clock);
      this.#emit(task, 'TASK_COMPLETED', { result: task.result });
      const snapshot = this.taskSnapshot(task.id);
      if (this.retention.maxCompletedTasks) {
        this.pruneState();
      }
      return snapshot;
    } catch (error) {
      task.status = 'FAILED';
      task.error = {
        code: error.code ?? 'PROVIDER_ERROR',
        message: error.message,
        details: error.details ?? {}
      };
      task.updated_at = nowIso(this.clock);
      this.#emit(task, 'TASK_FAILED', { error: task.error });
      const snapshot = this.taskSnapshot(task.id);
      if (this.retention.maxCompletedTasks) {
        this.pruneState();
      }
      return snapshot;
    }
  }

  #emit(task, type, payload = {}) {
    if (!TASK_STATES.has(task.status)) {
      throw new InvalidInputError(`Invalid task status: ${task.status}`, { task });
    }
    const event = {
      event: task.events.length + 1,
      type,
      task_id: task.id,
      timestamp: nowIso(this.clock),
      payload
    };
    task.events.push(event);
    task.updated_at = event.timestamp;
    this.auditEntries.push({
      type: 'TASK_EVENT',
      timestamp: event.timestamp,
      task_id: task.id,
      principal: task.principal,
      capability: task.capability_id,
      operation: task.capability_id,
      object: task.resource,
      ...(type === 'POLICY_DECISION'
        ? { decision: payload.decision === 'ask_approval' ? 'wait' : payload.decision, reason: payload.reason }
        : {}),
      event
    });
    this.#notifyTaskEventWatchers(task);
    return event;
  }

  #notifyTaskEventWatchers(task) {
    const watchers = this.taskEventWatchers.get(task.id);
    if (!watchers) return;

    for (const watcher of [...watchers]) {
      const events = task.events.filter((event) => event.event > watcher.sinceEvent);
      if (events.length === 0) continue;
      clearTimeout(watcher.timer);
      watchers.delete(watcher);
      watcher.resolve(events);
    }

    if (watchers.size === 0) {
      this.taskEventWatchers.delete(task.id);
    }
  }

  #removeTaskEventWatcher(taskId, watcher) {
    const watchers = this.taskEventWatchers.get(taskId);
    if (!watchers) return;
    watchers.delete(watcher);
    if (watchers.size === 0) {
      this.taskEventWatchers.delete(taskId);
    }
  }

  #getTask(taskId) {
    const task = this.tasks.get(taskId);
    if (!task) throw new NotFoundError(`Unknown task: ${taskId}`, { taskId });
    return task;
  }

  #decidePolicy(entry, input, options, { operation, sourceHandleRecord = null }) {
    return this.policyEngine.decide({
      capability: entry.capability,
      input,
      options,
      sourceHandleRecord,
      operation,
      resource: options.resource ?? null,
      grants: options.principal ? this.#listGrants({ principal: options.principal }) : [],
      now: this.clock?.() ?? new Date()
    });
  }

  async #resolveResource(entry, input, options) {
    const contractDigest = options.flow_contract_digest;
    const boundAcceptRecord = contractDigest
      ? [...this.flowAcceptPermits.values()].find((record) => record.contract_digest === contractDigest)
      : null;
    const acceptedResource = boundAcceptRecord?.contract.target.resource;
    const principal = options.principal ?? null;
    const resource =
      typeof entry.provider.resourceFor === 'function'
        ? await entry.provider.resourceFor({
          capability: entry.capability,
          input,
          options
        })
        : options.resource ?? null;
    if (boundAcceptRecord && resource !== acceptedResource) {
      throw this.#flowDenied(
        'FLOW_TARGET_RESOURCE_DENIED',
        'FLOW_TARGET_RESOURCE_CHANGED',
        'target canonical resource differs from the accepted flow contract',
        {
          contract_digest: contractDigest,
          principal,
          target_capability: entry.capability.id,
          accepted_resource: acceptedResource,
          target_resource: resource
        }
      );
    }
    return resource;
  }

  #assertHandlePrincipal(record, options, operation) {
    const owner = record.metadata.principal;
    if (!owner) return;
    if (!options.principal) {
      throw new HcpError('Handle access requires principal', 'MISSING_PRINCIPAL', {
        handle: record.handle,
        operation
      });
    }
    if (options.principal !== owner) {
      throw new HcpError('Handle access denied for principal', 'HANDLE_ACCESS_DENIED', {
        handle: record.handle,
        operation,
        principal: options.principal
      });
    }
  }

  #assertFlowArtifactActive(expiresAt, details = {}) {
    try {
      assertFlowActive(expiresAt, this.clock?.() ?? new Date(), details);
    } catch (error) {
      throw this.#flowDenied(
        'FLOW_ARTIFACT_DENIED',
        error.code ?? 'FLOW_ARTIFACT_INVALID',
        error.message,
        {
          ...structuredClone(details),
          expires_at: expiresAt
        }
      );
    }
  }

  #getTrustedFlowPeer(domainId) {
    const peer = this.flowPeers.get(domainId);
    if (!peer) {
      throw new HcpError('bilateral flow peer is not trusted', 'FLOW_PEER_NOT_TRUSTED', {
        domain_id: domainId
      });
    }
    return peer;
  }

  #verifyPeerFlowArtifact(artifact, expectedKind) {
    if (!artifact || artifact.kind !== expectedKind || artifact.protocol !== BILATERAL_FLOW_PROTOCOL) {
      throw this.#flowDenied(
        'FLOW_ARTIFACT_DENIED',
        'FLOW_ARTIFACT_INVALID',
        'unexpected bilateral flow artifact',
        {
          expected_kind: expectedKind,
          actual_kind: artifact?.kind,
          protocol: artifact?.protocol,
          issuer_domain: artifact?.issuer_domain
        }
      );
    }
    let peer;
    try {
      peer = this.#getTrustedFlowPeer(artifact.issuer_domain);
    } catch (error) {
      this.auditEntries.push({
        type: 'FLOW_ARTIFACT_DENIED',
        timestamp: nowIso(this.clock),
        domain_id: this.flowIdentity.domain_id,
        expected_kind: expectedKind,
        actual_kind: artifact.kind,
        issuer_domain: artifact.issuer_domain,
        artifact_digest: artifact.artifact_digest,
        allowed: false,
        reason: error.code ?? 'FLOW_PEER_NOT_TRUSTED',
        message: error.message
      });
      throw error;
    }
    if (!verifyFlowArtifact(artifact, peer.public_key_pem)) {
      throw this.#flowDenied(
        'FLOW_ARTIFACT_DENIED',
        'FLOW_SIGNATURE_INVALID',
        'bilateral flow artifact signature is invalid',
        {
          kind: artifact.kind,
          issuer_domain: artifact.issuer_domain,
          artifact_digest: artifact.artifact_digest
        }
      );
    }
    return peer;
  }

  #verifyOwnFlowArtifact(artifact, expectedKind) {
    if (
      !artifact ||
      artifact.kind !== expectedKind ||
      artifact.protocol !== BILATERAL_FLOW_PROTOCOL ||
      artifact.issuer_domain !== this.flowIdentity.domain_id ||
      !verifyFlowArtifact(artifact, this.flowIdentity.public_key_pem)
    ) {
      throw this.#flowDenied(
        'FLOW_ARTIFACT_DENIED',
        'FLOW_SIGNATURE_INVALID',
        'local bilateral flow artifact is invalid',
        {
          expected_kind: expectedKind,
          actual_kind: artifact?.kind,
          issuer_domain: artifact?.issuer_domain,
          artifact_digest: artifact?.artifact_digest
        }
      );
    }
  }

  #flowDenied(type, code, message, details = {}) {
    this.auditEntries.push({
      type,
      timestamp: nowIso(this.clock),
      domain_id: this.flowIdentity.domain_id,
      ...structuredClone(details),
      allowed: false,
      reason: code,
      message
    });
    return new HcpError(message, code, details);
  }

  #listGrants(filter = {}) {
    return [...this.grants.values()]
      .filter((grant) => !filter.principal || grant.principal === filter.principal)
      .filter((grant) => !filter.scope || grant.scopes.includes(filter.scope))
      .filter((grant) => !filter.resource || grant.resources.includes(filter.resource))
      .filter((grant) => !filter.capability || matchesGrantCapability(grant, filter.capability))
      .map((grant) => structuredClone(grant));
  }
}
