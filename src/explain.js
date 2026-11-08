function joinList(values = []) {
  return values.length > 0 ? values.join(', ') : 'none';
}

export function buildApprovalSummary(explanation = {}, capability = {}) {
  const effect = capability.effects?.kind ?? 'unknown';
  const risk = capability.effects?.risk ?? 'unknown';
  const approvalRequired = explanation.approval?.required === true;
  const approvalPresent = explanation.approval?.present === true;
  const lines = [
    `principal: ${explanation.principal ?? 'missing'}`,
    `action: ${explanation.capability ?? capability.id ?? 'unknown'}`,
    `resource: ${explanation.resource ?? 'unknown'}`,
    `required_scopes: ${joinList(explanation.required_scopes ?? [])}`,
    `effect: ${effect}`,
    `risk: ${risk}`,
    `approval: ${approvalRequired ? 'required' : 'not required'}; ${approvalPresent ? 'present' : 'not present'}`,
    `matched_grants: ${joinList(explanation.matched_grant_ids ?? [])}`,
    `decision: ${explanation.decision ?? 'unknown'}`,
    `reason: ${explanation.reason ?? 'none'}`
  ];

  return {
    principal: explanation.principal ?? null,
    action: explanation.capability ?? capability.id ?? null,
    resource: explanation.resource ?? null,
    required_scopes: explanation.required_scopes ?? [],
    effect,
    risk,
    approval_required: approvalRequired,
    approval_present: approvalPresent,
    matched_grant_ids: explanation.matched_grant_ids ?? [],
    decision: explanation.decision ?? null,
    reason: explanation.reason ?? null,
    text: lines.join('\n'),
    lines
  };
}

function describeAuditEntry(entry = {}) {
  switch (entry.type) {
    case 'POLICY_DECISION':
      return `policy ${entry.decision ?? entry.allowed}: ${entry.capability ?? 'unknown capability'} on ${entry.resource ?? 'unknown resource'} -> ${entry.reason ?? 'no reason'}`;
    case 'DATA_PUT':
      return `data stored as ${entry.handle ?? 'handle'} for ${entry.principal ?? 'unknown principal'}`;
    case 'DATA_PEEK':
      return `data peek ${entry.mode ?? 'preview'} allowed for ${entry.principal ?? 'unknown principal'} on ${entry.handle ?? 'handle'}`;
    case 'DATA_PEEK_DENIED':
      return `data peek denied for ${entry.principal ?? 'unknown principal'} on ${entry.handle ?? 'handle'}: ${entry.code ?? entry.reason ?? 'denied'}`;
    case 'DATA_REVOKED':
      return `handle revoked: ${entry.handle ?? 'handle'} (${entry.reason ?? 'no reason'})`;
    case 'DATA_PIPE_SOURCE_CHECK':
      return `pipe source check ${entry.allowed === false ? 'denied' : 'allowed'} for ${entry.source_handle ?? 'source handle'}`;
    case 'DATA_PIPE_POLICY_DECISION':
      return `pipe target policy ${entry.allowed === false ? 'denied' : 'allowed'} for ${entry.target_capability ?? 'target capability'} on ${entry.resource ?? 'resource'}: ${entry.reason ?? 'no reason'}`;
    case 'DATA_PIPE_STARTED_TASK':
      return `pipe started target task ${entry.target_task_id ?? 'unknown task'} via ${entry.pipe_id ?? 'pipe'}`;
    case 'TASK_EVENT':
      return `task event ${entry.event_type ?? entry.status ?? 'event'} for ${entry.task_id ?? 'task'}`;
    default:
      return `${entry.type ?? 'AUDIT_ENTRY'} recorded`;
  }
}

export function explainAuditTrace(trace = {}) {
  const policyDecisions = trace.policy_decisions ?? [];
  const auditEntries = trace.audit_entries ?? [];
  const denied = policyDecisions.filter((decision) => decision.decision === 'deny');
  const allowed = policyDecisions.filter((decision) => decision.decision === 'allow');
  const timeline = auditEntries.map((entry, index) => ({
    index,
    type: entry.type,
    timestamp: entry.timestamp ?? null,
    summary: describeAuditEntry(entry),
    entry
  }));
  const lines = [
    `task: ${trace.task_id ?? 'unknown'}`,
    `capability: ${trace.capability_id ?? 'unknown'}`,
    `status: ${trace.status ?? 'unknown'}`,
    `policy: ${allowed.length} allow, ${denied.length} deny`,
    `audit_entries: ${auditEntries.length}`
  ];

  if (trace.error) {
    lines.push(`error: ${trace.error.code ?? 'ERROR'} ${trace.error.message ?? ''}`.trim());
  }
  for (const item of timeline) {
    lines.push(`${item.index + 1}. ${item.summary}`);
  }

  return {
    task_id: trace.task_id ?? null,
    capability_id: trace.capability_id ?? null,
    status: trace.status ?? null,
    allow_count: allowed.length,
    deny_count: denied.length,
    audit_entry_count: auditEntries.length,
    text: lines.join('\n'),
    timeline
  };
}
