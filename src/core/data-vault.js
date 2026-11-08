import { HcpError, NotFoundError } from '../errors.js';
import { makeId, nowIso } from '../ids.js';
import { digest } from './hash.js';
import { applyRedactions, inferContentType, previewValue, summarizeValue } from './projection.js';

export class InMemoryDataVault {
  constructor({ runId = makeId('run'), clock, maxObjects = null } = {}) {
    this.runId = runId;
    this.clock = clock;
    this.maxObjects = Number.isInteger(maxObjects) && maxObjects > 0 ? maxObjects : null;
    this.objects = new Map();
  }

  put(value, metadata = {}) {
    const objectId = makeId('obj');
    const handle = `h://vault/${this.runId}/${objectId}`;
    const record = {
      handle,
      objectId,
      value,
      metadata: {
        data_class: metadata.data_class ?? ['internal'],
        content_type: metadata.content_type ?? inferContentType(value),
        source: metadata.source ?? 'runtime',
        owner_task_id: metadata.owner_task_id ?? null,
        ttl_ms: metadata.ttl_ms ?? null,
        immutable: metadata.immutable ?? true,
        ...metadata
      },
      created_at: nowIso(this.clock),
      expires_at: metadata.ttl_ms ? new Date((this.clock?.() ?? new Date()).getTime() + metadata.ttl_ms).toISOString() : null,
      revoked: false,
      digest: digest(value)
    };
    this.objects.set(handle, record);
    if (this.maxObjects) {
      this.prune({ maxObjects: this.maxObjects });
    }
    return handle;
  }

  get(handle) {
    const record = this.objects.get(handle);
    if (!record) {
      throw new NotFoundError(`Unknown handle: ${handle}`, { handle });
    }
    if (record.revoked) {
      throw new HcpError(`Handle has been revoked: ${handle}`, 'HANDLE_REVOKED', { handle });
    }
    if (record.expires_at && new Date(record.expires_at).getTime() <= (this.clock?.() ?? new Date()).getTime()) {
      record.value = null;
      throw new HcpError(`Handle has expired: ${handle}`, 'HANDLE_EXPIRED', { handle });
    }
    return record;
  }

  peek(handle, projection = {}) {
    const record = this.get(handle);
    const mode = projection.mode ?? 'preview';
    const maxBytes = projection.max_bytes ?? 4096;

    const response = {
      handle,
      ...(record.metadata.release_policy === 'pipe_only' ? {} : { digest: record.digest }),
      metadata: record.metadata,
      created_at: record.created_at,
      expires_at: record.expires_at
    };

    if (mode === 'metadata') {
      return response;
    }

    const redactions = Array.isArray(projection.redactions) ? projection.redactions : [];

    if (mode === 'summary') {
      const rawSummary = summarizeValue(record.value, projection.max_words ?? 80);
      return {
        ...response,
        summary: redactions.length > 0 ? applyRedactions(rawSummary, redactions) : rawSummary
      };
    }

    if (mode === 'full') {
      let value = record.value;
      if (redactions.length > 0) {
        value = typeof value === 'string'
          ? applyRedactions(value, redactions)
          : applyRedactions(JSON.stringify(value, null, 2), redactions);
      }
      return {
        ...response,
        value
      };
    }

    const rawPreview = previewValue(record.value, maxBytes);
    const preview = redactions.length > 0 ? applyRedactions(rawPreview, redactions) : rawPreview;
    return {
      ...response,
      preview,
      truncated: rawPreview.length < String(record.value).length
    };
  }

  revoke(handle, reason = 'unspecified') {
    const record = this.objects.get(handle);
    if (!record) {
      throw new NotFoundError(`Unknown handle: ${handle}`, { handle });
    }
    record.revoked = true;
    record.revoked_reason = reason;
    record.value = null;
    return { handle, revoked: true, reason };
  }

  prune({ maxObjects = this.maxObjects } = {}) {
    const nowMs = (this.clock?.() ?? new Date()).getTime();
    let scrubbed = 0;
    let evicted = 0;
    for (const record of this.objects.values()) {
      const expired = record.expires_at && new Date(record.expires_at).getTime() <= nowMs;
      if ((record.revoked || expired) && record.value !== null) {
        record.value = null;
        scrubbed += 1;
      }
    }
    const cap = Number.isInteger(maxObjects) && maxObjects > 0 ? maxObjects : null;
    if (cap !== null && this.objects.size > cap) {
      const excess = this.objects.size - cap;
      const keys = [...this.objects.keys()].slice(0, excess);
      for (const key of keys) {
        this.objects.delete(key);
        evicted += 1;
      }
    }
    return { scrubbed, evicted, remaining: this.objects.size };
  }
}
