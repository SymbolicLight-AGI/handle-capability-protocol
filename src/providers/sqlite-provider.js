import { InvalidInputError } from '../errors.js';

const IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function normalizeTables(tables = {}) {
  if (!tables || typeof tables !== 'object' || Array.isArray(tables)) {
    throw new InvalidInputError('sqlite provider requires tables object', { tables });
  }

  const normalized = new Map();
  for (const [tableName, rows] of Object.entries(tables)) {
    assertIdentifier(tableName, 'table');
    if (!Array.isArray(rows)) {
      throw new InvalidInputError('sqlite provider table rows must be an array', {
        table: tableName,
        rows
      });
    }
    normalized.set(tableName, rows.map((row) => {
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        throw new InvalidInputError('sqlite provider rows must be objects', {
          table: tableName,
          row
        });
      }
      return structuredClone(row);
    }));
  }
  return normalized;
}

function assertIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
    throw new InvalidInputError(`sqlite provider ${label} must be a simple identifier`, {
      [label]: value
    });
  }
}

function getRows(tables, tableName) {
  assertIdentifier(tableName, 'table');
  if (!tables.has(tableName)) {
    throw new InvalidInputError('sqlite provider table is not available', {
      table: tableName,
      available_tables: [...tables.keys()]
    });
  }
  return tables.get(tableName);
}

function normalizeColumns(columns, rows) {
  if (columns === undefined || columns === null) return null;
  if (!Array.isArray(columns) || columns.length === 0) {
    throw new InvalidInputError('sqlite provider columns must be a non-empty array', { columns });
  }
  const knownColumns = new Set(rows.flatMap((row) => Object.keys(row)));
  return columns.map((column) => {
    assertIdentifier(column, 'column');
    if (!knownColumns.has(column)) {
      throw new InvalidInputError('sqlite provider column is not available', {
        column,
        available_columns: [...knownColumns]
      });
    }
    return column;
  });
}

function normalizeWhere(where = {}) {
  if (!where || typeof where !== 'object' || Array.isArray(where)) {
    throw new InvalidInputError('sqlite provider where must be an object', { where });
  }
  for (const column of Object.keys(where)) {
    assertIdentifier(column, 'column');
  }
  return where;
}

function matchesWhere(row, where) {
  return Object.entries(where).every(([key, value]) => row[key] === value);
}

function projectRow(row, columns) {
  if (!columns) return structuredClone(row);
  return Object.fromEntries(columns.map((column) => [column, row[column]]));
}

function normalizeLimit(limit, maxRows) {
  if (limit === undefined || limit === null) return maxRows;
  if (!Number.isInteger(limit) || limit < 0) {
    throw new InvalidInputError('sqlite provider limit must be a non-negative integer', { limit });
  }
  return Math.min(limit, maxRows);
}

export function createSqliteProvider({
  tables = {},
  maxRows = 100
} = {}) {
  if (!Number.isInteger(maxRows) || maxRows <= 0) {
    throw new InvalidInputError('sqlite provider maxRows must be a positive integer', { maxRows });
  }
  const tableMap = normalizeTables(tables);

  return {
    async manifest() {
      return {
        provider: {
          id: 'sqlite.memory',
          version: '0.1.0',
          title: 'SQLite-like Memory Provider',
          description: 'Query configured in-memory tables with a small SQLite-shaped select primitive.'
        },
        capabilities: [
          {
            id: 'sqlite.query.select',
            version: '0.1.0',
            title: 'Select rows from table',
            description: 'Reads rows from a configured table, applies equality filters, and stores the result behind an HCP handle.',
            intents: ['query table', 'select rows', 'read structured data'],
            input_schema: {
              type: 'object',
              required: ['table'],
              properties: {
                table: { type: 'string' },
                columns: { type: 'array', items: { type: 'string' } },
                where: { type: 'object' },
                limit: { type: 'integer', minimum: 0 }
              }
            },
            output_schema: {
              type: 'object',
              properties: {
                table: { type: 'string' },
                handle: { type: 'string' },
                row_count: { type: 'integer' },
                truncated: { type: 'boolean' }
              }
            },
            effects: {
              kind: 'read',
              risk: 'low',
              dry_run: 'unsupported',
              idempotency: 'supported'
            },
            security: {
              required_scopes: ['sqlite:read'],
              resource_model: {
                type: 'canonical_provider_resource',
                format: 'sqlite:<table>'
              },
              data_in: ['query_filter'],
              data_out: ['structured_rows']
            }
          }
        ]
      };
    },

    async health() {
      return {
        status: 'ok',
        tables: [...tableMap.keys()],
        max_rows: maxRows,
        persistent: false
      };
    },

    resourceFor({ input }) {
      getRows(tableMap, input.table);
      return `sqlite:${input.table}`;
    },

    async invoke({ input, runtime, task }) {
      const rows = getRows(tableMap, input.table);
      const where = normalizeWhere(input.where ?? {});
      const columns = normalizeColumns(input.columns, rows);
      const limit = normalizeLimit(input.limit, maxRows);
      const matched = rows.filter((row) => matchesWhere(row, where));
      const selected = matched.slice(0, limit).map((row) => projectRow(row, columns));
      const handle = runtime.dataPut(selected, {
        principal: task.principal,
        capability: 'sqlite.query.select',
        resource: `sqlite:${input.table}`,
        task_id: task.task_id,
        data_class: ['structured_rows'],
        content_type: 'application/json',
        source: input.table,
        row_count: selected.length,
        truncated: matched.length > selected.length
      });

      return {
        table: input.table,
        handle,
        row_count: selected.length,
        truncated: matched.length > selected.length
      };
    }
  };
}
