import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify
} from 'node:crypto';
import { InvalidInputError } from './errors.js';
import { makeId } from './ids.js';

export const BILATERAL_FLOW_PROTOCOL = 'hcp.bilateral-flow/0.1';

function canonicalValue(value) {
  if (
    value === undefined ||
    typeof value === 'function' ||
    typeof value === 'symbol' ||
    typeof value === 'bigint'
  ) {
    throw new InvalidInputError('bilateral flow artifacts must contain JSON-compatible values', {
      value_type: typeof value
    });
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalValue(item));
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new InvalidInputError('bilateral flow artifacts require finite JSON numbers', {
      value
    });
  }
  if (Buffer.isBuffer(value)) {
    throw new InvalidInputError('bilateral flow artifacts must not contain raw buffers');
  }
  if (value && typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new InvalidInputError('bilateral flow artifacts must contain plain JSON objects', {
        object_type: value.constructor?.name ?? 'unknown'
      });
    }
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function flowDigest(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function publicKeyFingerprint(publicKeyPem) {
  const publicKey = createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new InvalidInputError('bilateral flow public key must be Ed25519', {
      asymmetric_key_type: publicKey.asymmetricKeyType
    });
  }
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

export function createFlowIdentity(input = {}) {
  const domainId = input.domain_id ?? input.domainId ?? makeId('domain');
  if (typeof domainId !== 'string' || domainId.length === 0) {
    throw new InvalidInputError('flow domain_id must be a non-empty string', { domain_id: domainId });
  }

  let privateKey;
  let publicKey;
  const privateKeyInput = input.private_key_pem ?? input.privateKeyPem;
  const publicKeyInput = input.public_key_pem ?? input.publicKeyPem;
  if (publicKeyInput && !privateKeyInput) {
    throw new InvalidInputError('bilateral flow identity cannot use a public key without a private key');
  }
  if (privateKeyInput) {
    privateKey = createPrivateKey(privateKeyInput);
    publicKey = createPublicKey(publicKeyInput ?? privateKey);
  } else {
    const generated = generateKeyPairSync('ed25519');
    privateKey = generated.privateKey;
    publicKey = generated.publicKey;
  }

  if (
    privateKey.asymmetricKeyType !== 'ed25519' ||
    publicKey.asymmetricKeyType !== 'ed25519'
  ) {
    throw new InvalidInputError('bilateral flow identity keys must be Ed25519', {
      private_key_type: privateKey.asymmetricKeyType,
      public_key_type: publicKey.asymmetricKeyType
    });
  }
  const keyProbe = Buffer.from('hcp.bilateral-flow/key-pair-check');
  const probeSignature = sign(null, keyProbe, privateKey);
  if (!verify(null, keyProbe, publicKey, probeSignature)) {
    throw new InvalidInputError('bilateral flow public and private keys do not form a pair');
  }

  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return {
    domain_id: domainId,
    private_key: privateKey,
    public_key: publicKey,
    public_key_pem: publicKeyPem,
    key_fingerprint: publicKeyFingerprint(publicKeyPem)
  };
}

export function signFlowArtifact(identity, unsignedArtifact) {
  const artifactDigest = flowDigest(unsignedArtifact);
  const signedPayload = {
    ...structuredClone(unsignedArtifact),
    artifact_digest: artifactDigest
  };
  const signature = sign(null, Buffer.from(canonicalJson(signedPayload)), identity.private_key).toString('base64url');
  return {
    ...signedPayload,
    signature
  };
}

export function verifyFlowArtifact(artifact, publicKeyPem) {
  if (!artifact || typeof artifact !== 'object' || typeof artifact.signature !== 'string') {
    return false;
  }
  try {
    const { signature, artifact_digest: artifactDigest, ...unsignedArtifact } = artifact;
    if (artifactDigest !== flowDigest(unsignedArtifact)) {
      return false;
    }
    const publicKey = createPublicKey(publicKeyPem);
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      return false;
    }
    const signedPayload = {
      ...unsignedArtifact,
      artifact_digest: artifactDigest
    };
    return verify(
      null,
      Buffer.from(canonicalJson(signedPayload)),
      publicKey,
      Buffer.from(signature, 'base64url')
    );
  } catch {
    return false;
  }
}

export function sameFlowValue(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}
