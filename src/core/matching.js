import { RISK_SCORE } from './constants.js';

export function normalizeText(value) {
  return String(value ?? '').toLowerCase();
}

export function tokenize(query) {
  return normalizeText(query)
    .split(/[^a-z0-9_.\-\u4e00-\u9fff]+/iu)
    .filter(Boolean);
}

export function matchesConstraints(capability, constraints = {}) {
  if (constraints.side_effects === 'read_only' && capability.effects.kind !== 'read') return false;
  if (constraints.effect && capability.effects.kind !== constraints.effect) return false;
  if (constraints.max_risk) {
    const capRisk = RISK_SCORE[capability.effects.risk ?? 'low'] ?? RISK_SCORE.low;
    const maxRisk = RISK_SCORE[constraints.max_risk] ?? RISK_SCORE.critical;
    if (capRisk > maxRisk) return false;
  }
  if (Array.isArray(constraints.domains) && constraints.domains.length > 0) {
    const haystack = `${capability.id} ${capability.title} ${capability.description ?? ''}`.toLowerCase();
    if (!constraints.domains.some((domain) => haystack.includes(String(domain).toLowerCase()))) {
      return false;
    }
  }
  return true;
}

export function matchesAuditFilter(entry, filter = {}) {
  if (filter.type && entry.type !== filter.type && entry.event?.type !== filter.type) return false;
  if (filter.task_id && entry.task_id !== filter.task_id) return false;
  if (filter.handle && entry.handle !== filter.handle && entry.source_handle !== filter.handle) return false;
  if (filter.principal && entry.principal !== filter.principal) return false;
  if (
    filter.capability &&
    entry.capability !== filter.capability &&
    entry.target_capability !== filter.capability &&
    entry.operation !== filter.capability
  ) {
    return false;
  }
  if (filter.resource && entry.resource !== filter.resource && entry.target_resource !== filter.resource) return false;
  if (filter.pipe_id && entry.pipe_id !== filter.pipe_id) return false;
  if (filter.contract_digest && entry.contract_digest !== filter.contract_digest) return false;
  if (filter.attempt_id && entry.attempt_id !== filter.attempt_id) return false;
  if (
    filter.decision &&
    String(entry.decision ?? '').toLowerCase() !== String(filter.decision).toLowerCase()
  ) {
    return false;
  }
  if (filter.reason && entry.reason !== filter.reason) return false;
  if (filter.since && new Date(entry.timestamp ?? entry.at).getTime() < new Date(filter.since).getTime()) return false;
  if (filter.until && new Date(entry.timestamp ?? entry.at).getTime() > new Date(filter.until).getTime()) return false;
  return true;
}

export function maxRisk(capabilities = []) {
  const risks = capabilities.map((capability) => capability.effects?.risk ?? 'low');
  return risks.reduce((highest, risk) => {
    const currentScore = RISK_SCORE[risk] ?? RISK_SCORE.low;
    const highestScore = RISK_SCORE[highest] ?? RISK_SCORE.low;
    return currentScore > highestScore ? risk : highest;
  }, 'low');
}

export function explainMatch(capability, terms, score) {
  const matched = terms.filter((term) =>
    `${capability.id} ${capability.title} ${capability.description ?? ''} ${(capability.intents ?? []).join(' ')}`
      .toLowerCase()
      .includes(term)
  );
  if (matched.length === 0) {
    return `Available ${capability.effects.kind} capability; baseline score ${score}.`;
  }
  return `Matched ${matched.join(', ')} against capability metadata.`;
}
