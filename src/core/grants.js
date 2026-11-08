import { HcpError, InvalidInputError } from '../errors.js';

export function isExpired(expiresAt, now = new Date()) {
  return Boolean(expiresAt) && new Date(expiresAt).getTime() <= now.getTime();
}

export function validateStringArray(value, field) {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new InvalidInputError(`${field} must be a non-empty string array`, { field, value });
  }
}

export function resolveGrantExpiresAt(input, now) {
  if (input.expires_at !== undefined && input.expires_at !== null) {
    const expiresAt = new Date(input.expires_at);
    if (Number.isNaN(expiresAt.getTime())) {
      throw new InvalidInputError('grant expires_at must be a valid date', { expires_at: input.expires_at });
    }
    return expiresAt.toISOString();
  }
  if (input.ttl_ms !== undefined) {
    if (!Number.isInteger(input.ttl_ms)) {
      throw new InvalidInputError('grant ttl_ms must be an integer', { ttl_ms: input.ttl_ms });
    }
    return new Date(now.getTime() + input.ttl_ms).toISOString();
  }
  return null;
}

export function resolveFlowExpiresAt(input, now) {
  if (input.expires_at !== undefined && input.expires_at !== null) {
    const expiresAt = new Date(input.expires_at);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= now.getTime()) {
      throw new InvalidInputError('flow expires_at must be a valid future date', {
        expires_at: input.expires_at
      });
    }
    return expiresAt.toISOString();
  }
  const ttlMs = input.ttl_ms ?? 5 * 60 * 1000;
  if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new InvalidInputError('flow ttl_ms must be a positive integer', { ttl_ms: ttlMs });
  }
  return new Date(now.getTime() + ttlMs).toISOString();
}

export function assertFlowActive(expiresAt, now, details = {}) {
  const expiry = new Date(expiresAt);
  if (typeof expiresAt !== 'string' || Number.isNaN(expiry.getTime())) {
    throw new HcpError('Bilateral flow artifact has an invalid expiry', 'FLOW_ARTIFACT_INVALID', {
      ...details,
      expires_at: expiresAt
    });
  }
  if (expiry.getTime() <= now.getTime()) {
    throw new HcpError('Bilateral flow artifact has expired', 'FLOW_EXPIRED', {
      ...details,
      expires_at: expiresAt
    });
  }
}

export function normalizeFlowMapping(mapping = {}) {
  if (mapping === null || typeof mapping !== 'object' || Array.isArray(mapping)) {
    throw new InvalidInputError('flow mapping must be an object', { mapping });
  }
  const targetField = mapping.target_field ?? 'body';
  if (typeof targetField !== 'string' || targetField.length === 0) {
    throw new InvalidInputError('flow mapping target_field must be a non-empty string', {
      target_field: targetField
    });
  }
  const input = mapping.input ?? {};
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new InvalidInputError('flow mapping input must be an object', { input });
  }
  return {
    target_field: targetField,
    input: structuredClone(input)
  };
}

export function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new InvalidInputError(`${field} must be a non-empty string`, { field, value });
  }
  return value;
}

export function matchesGrantCapability(grant, capabilityId) {
  return !Array.isArray(grant.capabilities) || grant.capabilities.length === 0 || grant.capabilities.includes(capabilityId);
}

// Discovery-time authority test. This is deliberately weaker than
// evaluateGrantAuthority: a resource is not known when a catalog is listed, so
// this answers only "could this principal hold authority for this capability at
// all", and it governs disclosure rather than invocation.
export function principalCanDiscoverCapability({ principal, capability, grants = [], now = new Date() }) {
  const requiredScopes = capability.security?.required_scopes ?? [];
  if (requiredScopes.length === 0) return true;
  if (!principal) return false;
  return grants.some(
    (grant) =>
      grant.principal === principal &&
      !grant.revoked_at &&
      !isExpired(grant.expires_at, now) &&
      requiredScopes.every((scope) => grant.scopes.includes(scope)) &&
      matchesGrantCapability(grant, capability.id)
  );
}

export function evaluateGrantAuthority({ principal, requiredScopes, resource, capabilityId, grants = [], now = new Date() }) {
  const details = {
    principal,
    capability: capabilityId,
    resource,
    required_scopes: requiredScopes,
    matched_grant_ids: [],
    allowed: false,
    reason: null
  };

  if (requiredScopes.length === 0) {
    return { ...details, allowed: true, reason: 'NO_REQUIRED_SCOPES' };
  }
  if (!principal) {
    return { ...details, reason: 'MISSING_PRINCIPAL' };
  }
  if (!resource) {
    return { ...details, reason: 'MISSING_RESOURCE' };
  }

  const principalGrants = grants.filter((grant) => grant.principal === principal);
  if (principalGrants.length === 0) {
    return { ...details, reason: 'MISSING_GRANT' };
  }

  const scopedGrants = principalGrants.filter((grant) => requiredScopes.every((scope) => grant.scopes.includes(scope)));
  if (scopedGrants.length === 0) {
    return { ...details, reason: 'INSUFFICIENT_SCOPE' };
  }

  const resourceGrants = scopedGrants.filter((grant) => grant.resources.includes(resource));
  if (resourceGrants.length === 0) {
    return { ...details, reason: 'RESOURCE_DENIED' };
  }

  const capabilityGrants = resourceGrants.filter((grant) => matchesGrantCapability(grant, capabilityId));
  if (capabilityGrants.length === 0) {
    return { ...details, reason: 'CAPABILITY_DENIED' };
  }

  const activeGrants = capabilityGrants.filter((grant) => !grant.revoked_at && !isExpired(grant.expires_at, now));
  if (activeGrants.length === 0) {
    const revokedGrant = capabilityGrants.find((grant) => grant.revoked_at);
    if (revokedGrant) {
      return {
        ...details,
        matched_grant_ids: [revokedGrant.id],
        reason: 'GRANT_REVOKED'
      };
    }

    const expiredGrant = capabilityGrants.find((grant) => isExpired(grant.expires_at, now));
    if (expiredGrant) {
      return {
        ...details,
        matched_grant_ids: [expiredGrant.id],
        reason: 'GRANT_EXPIRED'
      };
    }
  }

  return {
    ...details,
    matched_grant_ids: activeGrants.map((grant) => grant.id),
    allowed: true,
    reason: 'GRANT_MATCHED'
  };
}
