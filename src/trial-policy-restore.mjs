import { createHash } from 'node:crypto';

export const policyHash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function valid(policy) {
  if (policy?.schema !== 'aleph.trial-policy.v1' || !Number.isInteger(policy.version)
      || !Array.isArray(policy.rules) || new Set(policy.rules.map(rule => rule.id)).size !== policy.rules.length
      || policy.rules.some(rule => typeof rule.id !== 'string' || typeof rule.service !== 'string'
        || typeof rule.subject !== 'string' || typeof rule.path !== 'string'
        || !Array.isArray(rule.methods))) throw new Error('invalid_trial_policy');
}

export function previewPolicyRestore(snapshot, current, trustedHash) {
  if (!snapshot) throw new Error('verified_policy_backup_missing');
  valid(snapshot);
  valid(current);
  if (policyHash(snapshot) !== trustedHash) throw new Error('policy_backup_verification_failed');
  const saved = snapshot.rules.filter(rule => rule.service === 'notes');
  const existing = current.rules.filter(rule => rule.service === 'notes');
  const preview = {
    restoreFromVersion: snapshot.version,
    currentVersion: current.version,
    currentHash: policyHash(current),
    backupHash: trustedHash,
    service: 'notes',
    changes: { before: structuredClone(existing), after: structuredClone(saved) },
  };
  return { ...preview, confirmationHash: policyHash(preview) };
}

export function applyTrialPolicyRestore(snapshot, current, trustedHash, confirmationHash) {
  const preview = previewPolicyRestore(snapshot, current, trustedHash);
  if (confirmationHash !== preview.confirmationHash) throw new Error('policy_restore_confirmation_required');
  return {
    ...structuredClone(current),
    version: current.version + 1,
    restoredFromVersion: snapshot.version,
    rules: [
      ...structuredClone(current.rules.filter(rule => rule.service !== 'notes')),
      ...structuredClone(preview.changes.after),
    ],
  };
}

export function trialAllows(policy, request) {
  valid(policy);
  return policy.rules.some(rule => rule.service === request.service && rule.path === request.path
    && (rule.subject === request.subject || rule.subject === '*') && rule.methods.includes(request.method));
}
