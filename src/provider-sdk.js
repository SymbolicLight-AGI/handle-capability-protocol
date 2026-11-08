import { InvalidInputError } from './errors.js';

const REQUIRED_CAPABILITY_FIELDS = [
  'id',
  'version',
  'title',
  'input_schema',
  'output_schema',
  'effects',
  'security'
];

function clone(value) {
  return structuredClone(value);
}

export function buildCapabilityManifest({
  id,
  capability,
  version,
  title,
  description = '',
  intents = [],
  input_schema = { type: 'object' },
  output_schema = { type: 'object' },
  effects = { kind: 'read', risk: 'low' },
  security = {},
  runtime,
  attestation,
  metadata
} = {}) {
  const capabilityId = id ?? capability;
  const manifest = {
    id: capabilityId,
    capability: capabilityId,
    version,
    title,
    description,
    intents: [...intents],
    input_schema: clone(input_schema),
    output_schema: clone(output_schema),
    effects: clone(effects),
    security: {
      ...clone(security),
      required_scopes: [...(security.required_scopes ?? [])]
    }
  };

  if (runtime !== undefined) manifest.runtime = clone(runtime);
  if (attestation !== undefined) manifest.attestation = clone(attestation);
  if (metadata !== undefined) manifest.metadata = clone(metadata);

  return validateCapabilityManifest(manifest);
}

export class CapabilityManifestBuilder {
  constructor(id, { version, title, description = '' } = {}) {
    this.id = id;
    this.version = version;
    this.title = title;
    this.description = description;
    this.intents = [];
    this.inputSchema = { type: 'object' };
    this.outputSchema = { type: 'object' };
    this.effectsValue = { kind: 'read', risk: 'low' };
    this.securityValue = { required_scopes: [] };
    this.runtimeValue = undefined;
    this.attestationValue = undefined;
    this.metadataValue = undefined;
  }

  intent(text) {
    this.intents.push(text);
    return this;
  }

  input(schema) {
    this.inputSchema = clone(schema);
    return this;
  }

  output(schema) {
    this.outputSchema = clone(schema);
    return this;
  }

  effects(value) {
    this.effectsValue = clone(value);
    return this;
  }

  security(value) {
    this.securityValue = clone(value);
    return this;
  }

  runtime(value) {
    this.runtimeValue = clone(value);
    return this;
  }

  attestation(value) {
    this.attestationValue = clone(value);
    return this;
  }

  metadata(value) {
    this.metadataValue = clone(value);
    return this;
  }

  build() {
    return buildCapabilityManifest({
      id: this.id,
      version: this.version,
      title: this.title,
      description: this.description,
      intents: this.intents,
      input_schema: this.inputSchema,
      output_schema: this.outputSchema,
      effects: this.effectsValue,
      security: this.securityValue,
      runtime: this.runtimeValue,
      attestation: this.attestationValue,
      metadata: this.metadataValue
    });
  }
}

export function capabilityManifest(id, options = {}) {
  return new CapabilityManifestBuilder(id, options);
}

export function buildProviderManifest({
  provider,
  capabilities,
  compatibility,
  runtime,
  attestation
} = {}) {
  if (!provider || typeof provider !== 'object') {
    throw new InvalidInputError('Provider manifest builder requires provider metadata');
  }
  if (!Array.isArray(capabilities) || capabilities.length === 0) {
    throw new InvalidInputError('Provider manifest builder requires capabilities array');
  }

  const manifest = {
    provider: clone(provider),
    capabilities: capabilities.map((capability) => validateCapabilityManifest(clone(capability)))
  };

  if (compatibility !== undefined) manifest.compatibility = clone(compatibility);
  if (runtime !== undefined) manifest.runtime = clone(runtime);
  if (attestation !== undefined) manifest.attestation = clone(attestation);

  return validateProviderManifest(manifest);
}

export function validateCapabilityManifest(capability) {
  for (const field of REQUIRED_CAPABILITY_FIELDS) {
    if (capability[field] === undefined || capability[field] === null) {
      throw new InvalidInputError(`Capability manifest is missing required field: ${field}`, {
        capability
      });
    }
  }

  if (!/^[a-z0-9][a-z0-9_.-]*[a-z0-9]$/.test(capability.id)) {
    throw new InvalidInputError(`Invalid capability id: ${capability.id}`, { capability });
  }

  const validKinds = new Set(['read', 'write', 'execute', 'external_send']);
  if (!validKinds.has(capability.effects.kind)) {
    throw new InvalidInputError(`Invalid effects.kind for ${capability.id}: ${capability.effects.kind}`, {
      capability
    });
  }

  if (!Array.isArray(capability.security.required_scopes)) {
    throw new InvalidInputError(`security.required_scopes must be an array for ${capability.id}`, {
      capability
    });
  }

  return capability;
}

export function validateProviderManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new InvalidInputError('Provider manifest must be an object');
  }
  if (!manifest.provider || typeof manifest.provider !== 'object') {
    throw new InvalidInputError('Provider manifest must include provider metadata');
  }
  if (!Array.isArray(manifest.capabilities)) {
    throw new InvalidInputError('Provider manifest must include capabilities array');
  }

  for (const capability of manifest.capabilities) {
    validateCapabilityManifest(capability);
  }
  return manifest;
}

export function makeProvider({ manifest, health, invoke, resourceFor, cancel, checkpoint }) {
  if (typeof manifest !== 'function') {
    throw new InvalidInputError('Provider must implement manifest()');
  }
  if (typeof health !== 'function') {
    throw new InvalidInputError('Provider must implement health()');
  }
  if (typeof invoke !== 'function') {
    throw new InvalidInputError('Provider must implement invoke()');
  }
  return { manifest, health, invoke, resourceFor, cancel, checkpoint };
}
