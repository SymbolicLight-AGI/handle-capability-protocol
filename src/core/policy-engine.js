import { RISK_SCORE } from './constants.js';
import { digest } from './hash.js';
import { evaluateGrantAuthority } from './grants.js';

export class DefaultPolicyEngine {
  constructor({ denyCrossProviderPii = true } = {}) {
    this.denyCrossProviderPii = denyCrossProviderPii;
  }

  decide({ capability, options = {}, sourceHandleRecord = null, operation = 'invoke', resource = null, grants = [], now = new Date() }) {
    const effect = capability.effects?.kind ?? 'read';
    const risk = capability.effects?.risk ?? 'low';
    const obligations = ['audit.task_events'];
    const requiredScopes = capability.security?.required_scopes ?? [];
    const principal = options.principal ?? null;
    const grantAuthority = evaluateGrantAuthority({
      principal,
      requiredScopes,
      resource,
      capabilityId: capability.id,
      grants,
      now
    });

    if (!grantAuthority.allowed) {
      return policyDecision('deny', grantAuthority.reason, obligations, false, grantAuthority);
    }

    if (operation === 'data.pipe') {
      obligations.push('audit.data_flow');
      const sourceClasses = sourceHandleRecord?.metadata?.data_class ?? [];
      const targetDataIn = capability.security?.data_in ?? [];
      const hasPii = sourceClasses.includes('contains_pii') || sourceClasses.includes('pii');
      const targetAcceptsPii = targetDataIn.includes('contains_pii') || targetDataIn.includes('pii');
      if (this.denyCrossProviderPii && hasPii && !targetAcceptsPii) {
        return policyDecision('deny', 'target capability does not accept pii-class data', obligations, false, {
          source_data_class: sourceClasses,
          target_capability: capability.id
        });
      }
    }

    if (options.dry_run === true && capability.effects?.dry_run === 'supported') {
      return policyDecision('allow', 'dry-run operation', [...obligations, 'dry_run'], false);
    }

    const approvalMode = capability.security?.approval?.default;
    const needsApproval =
      effect === 'write' ||
      effect === 'execute' ||
      effect === 'external_send' ||
      approvalMode === 'required' ||
      RISK_SCORE[risk] >= RISK_SCORE.high;

    if (needsApproval && options.approval?.approved !== true) {
      return policyDecision('ask_approval', `${effect} operation requires approval`, obligations, true, {
        effect,
        risk,
        capability: capability.id,
        principal,
        resource,
        required_scopes: requiredScopes,
        matched_grant_ids: grantAuthority.matched_grant_ids,
        allowed: true,
        reason: 'APPROVAL_REQUIRED'
      });
    }

    return policyDecision('allow', effect === 'read' ? 'read-only capability' : 'approved operation', obligations, false, {
      effect,
      risk,
      capability: capability.id,
      principal,
      resource,
      required_scopes: requiredScopes,
      matched_grant_ids: grantAuthority.matched_grant_ids,
      allowed: true,
      reason: grantAuthority.reason
    });
  }
}

export function policyDecision(decision, reason, obligations, approvalRequired, details = {}) {
  return {
    decision,
    reason,
    obligations,
    approval_required: approvalRequired,
    policy_hash: digest({ decision, reason, obligations, approvalRequired, details }),
    details
  };
}
