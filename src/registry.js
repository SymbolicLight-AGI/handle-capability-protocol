import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { InvalidInputError, NotFoundError } from './errors.js';
import { validateProviderManifest } from './provider-sdk.js';

function digest(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  return `sha256:${createHash('sha256').update(raw).digest('hex')}`;
}

function providerFileName(providerId) {
  if (!/^[a-z0-9][a-z0-9_.-]*[a-z0-9]$/.test(providerId)) {
    throw new InvalidInputError(`Invalid provider id: ${providerId}`, { providerId });
  }
  return `${providerId}.json`;
}

const RISK_RANK = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

async function readManifestFile(filePath) {
  const raw = await readFile(filePath, 'utf8');
  return JSON.parse(raw);
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort();
}

function matchesText(value, query) {
  if (!query) return true;
  return String(value ?? '').toLowerCase().includes(String(query).toLowerCase());
}

function capabilitySummary(providerEntry, capability) {
  return {
    provider_id: providerEntry.provider_id,
    provider_version: providerEntry.provider_version,
    publisher: providerEntry.publisher,
    capability_id: capability.id,
    title: capability.title ?? capability.id,
    description: capability.description ?? '',
    effects: capability.effects ?? { kind: 'read', risk: 'low' },
    required_scopes: capability.security?.required_scopes ?? [],
    security: capability.security ?? {},
    compatibility: providerEntry.compatibility ?? {},
    manifest_digest: providerEntry.manifest_digest,
    signature_status: providerEntry.signature_status,
    supported_transports: providerEntry.supported_transports ?? []
  };
}

function matchesCapabilityFilter(summary, filter = {}) {
  if (filter.provider_id && summary.provider_id !== filter.provider_id) return false;
  if (filter.capability_id && summary.capability_id !== filter.capability_id) return false;
  if (filter.scope && !summary.required_scopes.includes(filter.scope)) return false;
  if (filter.effect && summary.effects.kind !== filter.effect) return false;
  if (filter.risk && summary.effects.risk !== filter.risk) return false;
  if (filter.transport && !summary.supported_transports.includes(filter.transport)) return false;
  if (filter.query) {
    return [
      summary.provider_id,
      summary.capability_id,
      summary.title,
      summary.description,
      ...summary.required_scopes
    ].some((value) => matchesText(value, filter.query));
  }
  return true;
}

function inferSignatureStatus(manifest) {
  const signature = manifest.attestation?.signature ?? manifest.provider?.attestation?.signature ?? null;
  if (!signature) return 'unsigned-dev';
  if (signature === 'optional-for-dev') return 'optional-for-dev';
  return 'declared-unverified';
}

function inferSupportedTransports(manifest) {
  const transports = manifest.provider?.supported_transports ?? manifest.provider?.transports ?? manifest.runtime?.transports;
  if (Array.isArray(transports) && transports.length > 0) {
    return uniqueSorted(transports);
  }
  return ['in_process'];
}

function inferSecurityProfile(manifest) {
  const capabilities = manifest.capabilities ?? [];
  const requiredScopes = uniqueSorted(capabilities.flatMap((capability) => capability.security?.required_scopes ?? []));
  const effectKinds = uniqueSorted(capabilities.map((capability) => capability.effects?.kind ?? 'read'));
  const dataClasses = uniqueSorted(capabilities.flatMap((capability) => [
    ...(capability.security?.data_in ?? []),
    ...(capability.security?.data_out ?? [])
  ]));
  const maxRisk = capabilities.reduce((current, capability) => {
    const risk = capability.effects?.risk ?? 'low';
    return (RISK_RANK[risk] ?? 0) > (RISK_RANK[current] ?? 0) ? risk : current;
  }, 'low');
  const approvalRequired = capabilities.some(
    (capability) =>
      capability.security?.approval?.default === 'required' ||
      ['write', 'execute', 'external_send'].includes(capability.effects?.kind)
  );

  return {
    required_scopes: requiredScopes,
    effects: effectKinds,
    max_risk: maxRisk,
    approval_required: approvalRequired,
    data_classes: dataClasses
  };
}

export function validateRegistryManifest(manifest) {
  const validated = validateProviderManifest(manifest);
  const manifestDigest = digest(validated);
  return {
    provider_id: validated.provider.id,
    provider_version: validated.provider.version ?? null,
    publisher: validated.provider.publisher ?? validated.attestation?.publisher ?? validated.provider.id,
    capabilities: validated.capabilities.map((capability) => capability.id),
    manifest_digest: manifestDigest,
    signature_status: inferSignatureStatus(validated),
    compatibility: validated.compatibility ?? {},
    security_profile: inferSecurityProfile(validated),
    supported_transports: inferSupportedTransports(validated),
    manifest: validated
  };
}

export class LocalManifestRegistry {
  constructor({ root }) {
    if (!root) throw new InvalidInputError('Local registry requires root directory');
    this.root = path.resolve(root);
  }

  async ensure() {
    await mkdir(this.root, { recursive: true });
    return { root: this.root };
  }

  async validateManifestFile(filePath) {
    return validateRegistryManifest(await readManifestFile(filePath));
  }

  async installManifestFile(filePath) {
    await this.ensure();
    const record = await this.validateManifestFile(filePath);
    const target = path.join(this.root, providerFileName(record.provider_id));
    await writeFile(target, JSON.stringify({
      provider_id: record.provider_id,
      provider_version: record.provider_version,
      publisher: record.publisher,
      capabilities: record.capabilities,
      manifest_digest: record.manifest_digest,
      signature_status: record.signature_status,
      compatibility: record.compatibility,
      security_profile: record.security_profile,
      supported_transports: record.supported_transports,
      installed_at: new Date().toISOString(),
      manifest: record.manifest
    }, null, 2), 'utf8');
    return {
      ...record,
      path: target
    };
  }

  async publishLocalManifestFile(filePath) {
    const installed = await this.installManifestFile(filePath);
    return {
      ...installed,
      published: true,
      mode: 'local'
    };
  }

  async get(providerId) {
    await this.ensure();
    const filePath = path.join(this.root, providerFileName(providerId));
    try {
      return JSON.parse(await readFile(filePath, 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new NotFoundError(`Provider is not installed: ${providerId}`, { providerId });
      }
      throw error;
    }
  }

  async list() {
    await this.ensure();
    const entries = [];
    for (const file of await readdir(this.root)) {
      if (!file.endsWith('.json')) continue;
      const entry = JSON.parse(await readFile(path.join(this.root, file), 'utf8'));
      entries.push({
        provider_id: entry.provider_id,
        provider_version: entry.provider_version,
        publisher: entry.publisher,
        capabilities: entry.capabilities,
        manifest_digest: entry.manifest_digest,
        signature_status: entry.signature_status,
        compatibility: entry.compatibility,
        security_profile: entry.security_profile,
        supported_transports: entry.supported_transports,
        installed_at: entry.installed_at
      });
    }
    entries.sort((a, b) => a.provider_id.localeCompare(b.provider_id));
    return entries;
  }

  async discover(filter = {}) {
    await this.ensure();
    const providers = [];
    const capabilities = [];

    for (const file of await readdir(this.root)) {
      if (!file.endsWith('.json')) continue;
      const entry = JSON.parse(await readFile(path.join(this.root, file), 'utf8'));
      const providerSummary = {
        provider_id: entry.provider_id,
        provider_version: entry.provider_version,
        publisher: entry.publisher,
        capabilities: entry.capabilities,
        manifest_digest: entry.manifest_digest,
        signature_status: entry.signature_status,
        compatibility: entry.compatibility,
        security_profile: entry.security_profile,
        supported_transports: entry.supported_transports,
        installed_at: entry.installed_at
      };
      const capabilitySummaries = (entry.manifest?.capabilities ?? []).map((capability) =>
        capabilitySummary(entry, capability)
      );
      const matchedCapabilities = capabilitySummaries.filter((summary) => matchesCapabilityFilter(summary, filter));
      const providerMatches =
        (!filter.query || [
          providerSummary.provider_id,
          providerSummary.publisher,
          ...(providerSummary.capabilities ?? [])
        ].some((value) => matchesText(value, filter.query))) &&
        (!filter.provider_id || providerSummary.provider_id === filter.provider_id) &&
        (!filter.transport || (providerSummary.supported_transports ?? []).includes(filter.transport));

      if (providerMatches || matchedCapabilities.length > 0) {
        const { query, ...nonQueryFilter } = filter;
        const requiresCapabilityMatch = Boolean(filter.capability_id || filter.scope || filter.effect || filter.risk);
        const selectedCapabilities = providerMatches
          ? capabilitySummaries.filter((summary) => matchesCapabilityFilter(summary, nonQueryFilter))
          : matchedCapabilities;
        if (requiresCapabilityMatch && selectedCapabilities.length === 0) continue;
        providers.push(providerSummary);
        capabilities.push(...selectedCapabilities);
      }
    }

    providers.sort((a, b) => a.provider_id.localeCompare(b.provider_id));
    capabilities.sort((a, b) => `${a.provider_id}:${a.capability_id}`.localeCompare(`${b.provider_id}:${b.capability_id}`));
    return {
      filter: structuredClone(filter),
      providers,
      capabilities,
      counts: {
        providers: providers.length,
        capabilities: capabilities.length
      }
    };
  }

  async verify(providerId) {
    const entry = await this.get(providerId);
    const record = validateRegistryManifest(entry.manifest);
    return {
      provider_id: providerId,
      expected_digest: entry.manifest_digest,
      actual_digest: record.manifest_digest,
      verified: entry.manifest_digest === record.manifest_digest,
      capabilities: record.capabilities,
      signature_status: record.signature_status,
      security_profile: record.security_profile,
      supported_transports: record.supported_transports
    };
  }
}

export function createLocalManifestRegistry(options) {
  return new LocalManifestRegistry(options);
}
