import { InvalidInputError } from '../errors.js';

function parsePageUrl(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidInputError('browser mock provider url must be a non-empty string', { url: value });
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new InvalidInputError('browser mock provider url must be a valid URL', { url: value });
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new InvalidInputError('browser mock provider url must use http or https', { url: value });
  }
  return url;
}

function normalizePages(pages = {}) {
  if (!pages || typeof pages !== 'object' || Array.isArray(pages)) {
    throw new InvalidInputError('browser mock provider requires pages object', { pages });
  }

  const normalized = new Map();
  for (const [urlValue, page] of Object.entries(pages)) {
    const url = parsePageUrl(urlValue);
    if (!page || typeof page !== 'object' || Array.isArray(page)) {
      throw new InvalidInputError('browser mock provider page fixture must be an object', {
        url: url.href,
        page
      });
    }
    normalized.set(url.href, {
      title: String(page.title ?? ''),
      text: String(page.text ?? ''),
      html: page.html === undefined ? null : String(page.html),
      links: Array.isArray(page.links) ? page.links.map(String) : [],
      metadata: page.metadata && typeof page.metadata === 'object' && !Array.isArray(page.metadata)
        ? structuredClone(page.metadata)
        : {}
    });
  }
  return normalized;
}

function getPage(pages, url) {
  const page = pages.get(url.href);
  if (!page) {
    throw new InvalidInputError('browser mock provider page is not available', {
      url: url.href,
      available_urls: [...pages.keys()]
    });
  }
  return page;
}

function selectSnapshot(page, includeHtml = false) {
  const snapshot = {
    title: page.title,
    text: page.text,
    links: [...page.links],
    metadata: structuredClone(page.metadata)
  };
  if (includeHtml) snapshot.html = page.html;
  return snapshot;
}

export function createBrowserMockProvider({
  pages = {}
} = {}) {
  const pageMap = normalizePages(pages);

  return {
    async manifest() {
      return {
        provider: {
          id: 'browser.mock',
          version: '0.1.0',
          title: 'Browser Mock Provider',
          description: 'Return deterministic page snapshots from configured fixtures without launching a browser.'
        },
        capabilities: [
          {
            id: 'browser.page.snapshot',
            version: '0.1.0',
            title: 'Read mock page snapshot',
            description: 'Reads a fixture-backed page snapshot and stores the page content behind an HCP handle.',
            intents: ['read page', 'inspect browser page', 'browser snapshot'],
            input_schema: {
              type: 'object',
              required: ['url'],
              properties: {
                url: { type: 'string' },
                include_html: { type: 'boolean', default: false }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                url: { type: 'string' },
                title: { type: 'string' },
                handle: { type: 'string' },
                bytes: { type: 'integer' }
              }
            },
            effects: {
              kind: 'read',
              risk: 'low',
              dry_run: 'unsupported',
              idempotency: 'supported'
            },
            security: {
              required_scopes: ['browser:read'],
              resource_model: {
                type: 'canonical_provider_resource',
                format: 'browser:<origin>'
              },
              data_in: ['url'],
              data_out: ['page_snapshot']
            }
          }
        ]
      };
    },

    async health() {
      return {
        status: 'ok',
        pages: [...pageMap.keys()],
        real_browser: false,
        network: false
      };
    },

    resourceFor({ input }) {
      const url = parsePageUrl(input.url);
      getPage(pageMap, url);
      return `browser:${url.origin}`;
    },

    async invoke({ input, runtime, task }) {
      const url = parsePageUrl(input.url);
      const page = getPage(pageMap, url);
      const snapshot = selectSnapshot(page, input.include_html === true);
      const handle = runtime.dataPut(snapshot, {
        principal: task.principal,
        capability: 'browser.page.snapshot',
        resource: `browser:${url.origin}`,
        task_id: task.task_id,
        data_class: ['page_snapshot'],
        content_type: 'application/json',
        source: url.href,
        owner_task_id: task.task_id
      });

      return {
        url: url.href,
        title: page.title,
        handle,
        bytes: Buffer.byteLength(JSON.stringify(snapshot))
      };
    }
  };
}
