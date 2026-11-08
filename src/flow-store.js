import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

/** Domain-local durable state. Transactions are synchronous and never span I/O. */
export class FlowStore {
  constructor({ path, domainId, busyTimeoutMs = 5000 }) {
    if (!path || !domainId) throw new TypeError('FlowStore requires path and domainId');
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 0) throw new TypeError('invalid busyTimeoutMs');
    mkdirSync(dirname(path), { recursive: true });
    this.path = path;
    this.domainId = domainId;
    this.transactionDepth = 0;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=${busyTimeoutMs}; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;`);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS records (
        namespace TEXT NOT NULL, key TEXT NOT NULL, version INTEGER NOT NULL,
        value TEXT NOT NULL, PRIMARY KEY(namespace, key)
      );
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS effects (
        effect_key TEXT PRIMARY KEY, value TEXT NOT NULL
      );
    `);
    try {
      this.transaction(() => {
        const row = this.db.prepare('SELECT value FROM metadata WHERE key=?').get('domain_id');
        if (row && row.value !== domainId) throw new Error('FlowStore domain identity does not match database');
        this.db.prepare('INSERT OR IGNORE INTO metadata(key,value) VALUES (?,?)').run('domain_id', domainId);
        this.db.prepare('INSERT OR IGNORE INTO metadata(key,value) VALUES (?,?)').run('format_version', '1');
      });
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  transaction(fn) {
    if (fn?.constructor?.name === 'AsyncFunction') throw new TypeError('FlowStore transactions must not await');
    // A nested operation belongs to the outer transaction, including its rollback.
    if (this.transactionDepth) {
      const value = fn(this);
      if (value && typeof value.then === 'function') throw new TypeError('FlowStore transactions must not await');
      return value;
    }
    this.db.exec('BEGIN IMMEDIATE');
    this.transactionDepth += 1;
    try {
      const result = fn(this);
      if (result && typeof result.then === 'function') throw new TypeError('FlowStore transactions must not await');
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    } finally {
      this.transactionDepth -= 1;
    }
  }

  read(namespace, key) {
    const row = this.db.prepare('SELECT version,value FROM records WHERE namespace=? AND key=?').get(namespace, key);
    return row ? { version: row.version, value: JSON.parse(row.value) } : null;
  }

  get(namespace, key) { return this.read(namespace, key)?.value ?? null; }

  put(namespace, key, value, { expectedVersion } = {}) {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError('FlowStore values must be JSON serializable');
    return this.transaction(() => {
      const current = this.read(namespace, key);
      // A missing record has version 0. This permits an atomic insert-only update.
      if (expectedVersion !== undefined && (current?.version ?? 0) !== expectedVersion) {
        return { updated: false, ...current };
      }
      const version = (current?.version ?? 0) + 1;
      this.db.prepare(`INSERT INTO records(namespace,key,version,value) VALUES (?,?,?,?)
        ON CONFLICT(namespace,key) DO UPDATE SET version=excluded.version,value=excluded.value`).run(namespace, key, version, encoded);
      return { updated: true, version, value: JSON.parse(encoded) };
    });
  }

  /** Recheck a state and policy predicates while holding the same local write transaction. */
  transition(namespace, key, { fromStates, toState, patch = {}, expectedVersion, predicate } = {}) {
    if (!Array.isArray(fromStates) || typeof toState !== 'string') throw new TypeError('transition requires fromStates and toState');
    return this.transaction(() => {
      const current = this.read(namespace, key);
      if (!current || !fromStates.includes(current.value.state) ||
          (expectedVersion !== undefined && current.version !== expectedVersion)) {
        return { updated: false, ...current };
      }
      if (predicate) {
        const allowed = predicate(current.value, this);
        if (allowed && typeof allowed.then === 'function') throw new TypeError('transition predicate must be synchronous');
        if (!allowed) return { updated: false, ...current };
      }
      return this.put(namespace, key, { ...current.value, ...patch, state: toState }, { expectedVersion: current.version });
    });
  }

  /** A claim is never silently released by restart or by an owner timeout. */
  claimOnce(namespace, key, value) {
    return this.transaction(() => {
      const current = this.read(namespace, key);
      if (current) return { claimed: false, ...current };
      const result = this.put(namespace, key, value, { expectedVersion: 0 });
      return { claimed: result.updated, version: result.version, value: result.value };
    });
  }

  // Snapshots are caller-selected JSON data. Domain signing/TLS private keys stay outside this store.
  saveSnapshot(name, snapshot, options) { return this.put('snapshots', name, snapshot, options); }
  loadSnapshot(name) { return this.get('snapshots', name); }
  readSnapshot(name) { return this.read('snapshots', name); }

  appendEvent(category, event) {
    const encoded = JSON.stringify(event);
    if (encoded === undefined) throw new TypeError('event must be JSON serializable');
    const row = this.db.prepare('INSERT INTO events(category,value) VALUES (?,?)').run(category, encoded);
    return Number(row.lastInsertRowid);
  }

  listEvents({ category, afterId = 0 } = {}) {
    const rows = category === undefined
      ? this.db.prepare('SELECT id,category,value FROM events WHERE id>? ORDER BY id').all(afterId)
      : this.db.prepare('SELECT id,category,value FROM events WHERE id>? AND category=? ORDER BY id').all(afterId, category);
    return rows.map((row) => ({ id: row.id, category: row.category, value: JSON.parse(row.value) }));
  }

  /** Experimental transaction sink only; this does not make remote Provider effects atomic. */
  recordEffectOnce(effectKey, effect) {
    const encoded = JSON.stringify(effect);
    if (encoded === undefined) throw new TypeError('effect must be JSON serializable');
    return this.transaction(() => {
      const previous = this.db.prepare('SELECT value FROM effects WHERE effect_key=?').get(effectKey);
      if (previous) return { recorded: false, effect: JSON.parse(previous.value) };
      this.db.prepare('INSERT INTO effects(effect_key,value) VALUES (?,?)').run(effectKey, encoded);
      return { recorded: true, effect: JSON.parse(encoded) };
    });
  }

  listEffects() {
    return this.db.prepare('SELECT effect_key,value FROM effects ORDER BY rowid').all()
      .map((row) => ({ effect_key: row.effect_key, ...JSON.parse(row.value) }));
  }

  info() {
    return {
      domain_id: this.domainId,
      path: this.path,
      journal_mode: this.db.prepare('PRAGMA journal_mode').get().journal_mode,
      synchronous: this.db.prepare('PRAGMA synchronous').get().synchronous,
      records: this.db.prepare('SELECT count(*) AS count FROM records').get().count,
      events: this.db.prepare('SELECT count(*) AS count FROM events').get().count,
      effects: this.db.prepare('SELECT count(*) AS count FROM effects').get().count
    };
  }

  readonlyStats() {
    const bytes = (file) => { try { return statSync(file).size; } catch { return 0; } };
    return { ...this.info(), database_bytes: bytes(this.path), wal_bytes: bytes(`${this.path}-wal`),
      shm_bytes: bytes(`${this.path}-shm`) };
  }

  checkpoint() { return this.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get(); }
  close() { this.db.close(); }
}
