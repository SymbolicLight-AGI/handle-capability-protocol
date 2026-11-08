const SENSITIVE_SECRET_RULES = [
  {
    id: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    replacement: '[redacted:private_key]'
  },
  {
    id: 'openai_api_key',
    pattern: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}\b/g,
    replacement: '[redacted:api_key]'
  },
  {
    id: 'github_token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
    replacement: '[redacted:github_token]'
  },
  {
    id: 'aws_access_key',
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replacement: '[redacted:aws_key]'
  },
  {
    id: 'bearer_token',
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/gi,
    replacement: 'Bearer [redacted:token]'
  },
  {
    id: 'env_secret_assignment',
    pattern: /\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[A-Z0-9_]*)\s*([=:])\s*([^\s"',;}{]{6,})/gi,
    replacement: '$1$2[redacted:secret]'
  }
];

export function detectSensitiveSecrets(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const findings = [];
  for (const rule of SENSITIVE_SECRET_RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    if (regex.test(text)) {
      findings.push(rule.id);
    }
  }
  return findings;
}

export function redactSensitiveSecrets(value) {
  let out = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  for (const rule of SENSITIVE_SECRET_RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    out = out.replace(regex, rule.replacement);
  }
  return out;
}

export function previewValue(value, maxBytes = 4096) {
  if (typeof value === 'string') {
    return value.slice(0, maxBytes);
  }
  const json = JSON.stringify(value, null, 2);
  return json.slice(0, maxBytes);
}

export function summarizeValue(value, maxWords = 80) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const words = text.split(/\s+/).filter(Boolean);
  return words.slice(0, maxWords).join(' ') + (words.length > maxWords ? ' …' : '');
}

export function applyRedactions(text, redactions = []) {
  let out = text;
  if (redactions.includes('email')) {
    out = out.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[redacted:email]');
  }
  if (redactions.includes('phone')) {
    out = out.replace(/(?<!\d)(?:\+?\d[\d\s().-]{6,}\d)(?!\d)/g, '[redacted:phone]');
  }
  if (redactions.includes('secret') || redactions.includes('secrets')) {
    out = redactSensitiveSecrets(out);
  }
  return out;
}

export function applyTransform(value, transform = {}) {
  let out = typeof value === 'string' ? value : JSON.stringify(value, null, 2);

  if (Array.isArray(transform.redact)) {
    out = applyRedactions(out, transform.redact);
  }

  if (transform.type === 'summarize') {
    out = summarizeValue(out, transform.max_words ?? 120);
  }

  if (Number.isInteger(transform.max_bytes) && transform.max_bytes >= 0) {
    let bytes = 0;
    let prefix = '';
    for (const character of out) {
      const size = Buffer.byteLength(character, 'utf8');
      if (bytes + size > transform.max_bytes) break;
      prefix += character;
      bytes += size;
    }
    out = prefix;
  }

  return out;
}

export function inferContentType(value) {
  if (typeof value === 'string') return 'text/plain';
  if (Buffer.isBuffer(value)) return 'application/octet-stream';
  return 'application/json';
}
