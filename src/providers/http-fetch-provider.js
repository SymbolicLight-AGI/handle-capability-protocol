import { InvalidInputError } from '../errors.js';

function parseUrl(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidInputError('url must be a non-empty string', { url: value });
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new InvalidInputError('url must be a valid URL', { url: value });
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new InvalidInputError('url must use http or https', { url: value });
  }
  return url;
}

function normalizeAllowedOrigins(allowedOrigins = []) {
  return new Set(allowedOrigins.map((origin) => new URL(origin).origin));
}

function assertAllowedOrigin(url, allowedOrigins) {
  if (allowedOrigins.size > 0 && !allowedOrigins.has(url.origin)) {
    throw new InvalidInputError('url origin is not allowed for http.fetch provider', {
      origin: url.origin,
      allowed_origins: [...allowedOrigins]
    });
  }
}

function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === 'function') return headers.get(name);
  return headers[name] ?? headers[name.toLowerCase()] ?? null;
}

export function createHttpFetchProvider({
  allowedOrigins = [],
  fetchImpl = globalThis.fetch,
  maxBytes = 64 * 1024
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new InvalidInputError('http.fetch provider requires fetch implementation');
  }
  const allowedOriginSet = normalizeAllowedOrigins(allowedOrigins);

  return {
    async manifest() {
      return {
        provider: {
          id: 'http.fetch',
          version: '0.1.0',
          title: 'HTTP Fetch Provider',
          description: 'Fetch HTTP/HTTPS resources from an explicit allowlist.'
        },
        capabilities: [
          {
            id: 'http.fetch.get',
            version: '0.1.0',
            title: 'Fetch HTTP resource',
            description: 'Fetch a URL with GET and store the response body behind an HCP handle.',
            intents: ['fetch url', 'read http resource', 'download text'],
            input_schema: {
              type: 'object',
              required: ['url'],
              properties: {
                url: { type: 'string' },
                headers: { type: 'object' }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                url: { type: 'string' },
                status: { type: 'number' },
                content_type: { type: 'string' },
                handle: { type: 'string' },
                bytes: { type: 'number' }
              }
            },
            effects: {
              kind: 'read',
              risk: 'medium',
              dry_run: 'unsupported',
              idempotency: 'supported'
            },
            security: {
              required_scopes: ['http:fetch'],
              resource_model: {
                type: 'canonical_provider_resource',
                format: 'http:<origin>'
              },
              data_in: ['url'],
              data_out: ['external_content']
            }
          }
        ]
      };
    },

    async health() {
      return { status: 'ok', allowed_origins: [...allowedOriginSet] };
    },

    resourceFor({ input }) {
      const url = parseUrl(input.url);
      assertAllowedOrigin(url, allowedOriginSet);
      return `http:${url.origin}`;
    },

    async invoke({ input, runtime, task }) {
      const url = parseUrl(input.url);
      assertAllowedOrigin(url, allowedOriginSet);
      const response = await fetchImpl(url.href, {
        method: 'GET',
        headers: input.headers ?? {}
      });
      const text = await response.text();
      const body = text.slice(0, maxBytes);
      const contentType = headerValue(response.headers, 'content-type') ?? 'application/octet-stream';
      const handle = runtime.dataPut(body, {
        principal: task.principal,
        capability: 'http.fetch.get',
        resource: `http:${url.origin}`,
        task_id: task.task_id,
        data_class: ['external_content'],
        content_type: contentType,
        source: url.href,
        truncated: text.length > body.length
      });

      return {
        url: url.href,
        status: response.status,
        content_type: contentType,
        handle,
        bytes: body.length,
        truncated: text.length > body.length
      };
    }
  };
}
