import test from 'node:test';
import assert from 'node:assert/strict';
import { policyHash, previewPolicyRestore, applyTrialPolicyRestore, trialAllows } from '../src/trial-policy-restore.mjs';
import { createRestoreHandler } from '../src/restore-api.mjs';

test('verified trial backup previews version and scope, then restores A access while preserving other rules and audit', () => {
  const snapshot = {
    schema: 'aleph.trial-policy.v1',
    version: 1,
    rules: [
      { id: 'note_a', service: 'notes', subject: 'synthetic_a', path: '/notes/note-a', methods: ['GET', 'PUT'] },
    ],
  };
  const current = { ...structuredClone(snapshot), version: 2, audit: ['synthetic_history'] };
  current.rules[0].subject = '*';
  current.rules.push({ id: 'other_service', service: 'notices', subject: 'synthetic_instructor', path: '/notices/demo', methods: ['GET'] });
  const before = structuredClone(current);
  const trusted = policyHash(snapshot);
  const preview = previewPolicyRestore(snapshot, current, trusted);
  assert.equal(preview.restoreFromVersion, 1);
  assert.equal(preview.service, 'notes');
  assert.deepEqual(current, before);
  assert.throws(() => applyTrialPolicyRestore(snapshot, current, trusted, 'not_confirmed'), /confirmation_required/);
  const restored = applyTrialPolicyRestore(snapshot, current, trusted, preview.confirmationHash);
  assert.deepEqual(restored.audit, current.audit);
  assert.deepEqual(restored.rules[0], current.rules[1]);
  const own = { service: 'notes', path: '/notes/note-a', subject: 'synthetic_a', method: 'GET' };
  assert.equal(trialAllows(restored, own), true);
  assert.equal(trialAllows(restored, { ...own, subject: 'synthetic_b' }), false);
  assert.throws(() => previewPolicyRestore(null, current, trusted), /backup_missing/);
  assert.throws(() => previewPolicyRestore({ ...snapshot, version: 0 }, current, trusted), /verification_failed/);
});

const id = 'aabbccdd-1234-4567-89ab-123456789abc';
async function invoke({
  login = { kind: 'judge', identity: 'b', userId: 'synthetic_b' },
  data = { restored: true, noteId: id, contentSha256: 'a'.repeat(64) },
  url = '/api/restore/' + id,
  body,
  method = 'POST',
} = {}) {
  const calls = [];
  const db = {
    async rpc(name, args) {
      calls.push([name, args]);
      return { data, error: null };
    },
  };
  const res = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await createRestoreHandler({
    db,
    verifyLogin: async () => login,
    policyDigest: async () => 'b'.repeat(64),
  })({ method, url, body, headers: {} }, res);
  return { res, calls };
}

test('restore uses verified B owner and exact ID, and never accepts client owner/content', async () => {
  const result = await invoke();
  assert.equal(result.res.code, 200);
  assert.equal(result.calls[0][1].p_owner_id, 'synthetic_b');
  for (const options of [
    { login: null },
    { login: { kind: 'student', identity: 'b', userId: 'synthetic_b' } },
    { login: { kind: 'judge', identity: 'a', userId: 'synthetic_a' } },
    { url: '/api/restore/' + id + '?noteId=other' },
  ]) {
    const denied = await invoke(options);
    assert.notEqual(denied.res.code, 200);
    assert.equal(denied.calls.length, 0);
  }
});

test('restore ignores any request body and extra query values; only the path ID and verified owner are used', async () => {
  const result = await invoke({ body: { owner_id: 'other', title: 'replacement', content: 'evil' }, url: '/api/restore/' + id + '?x=1&owner=other' });
  assert.equal(result.res.code, 200);
  assert.deepEqual(Object.keys(result.calls[0][1]).sort(), ['p_note_id', 'p_owner_id', 'p_policy_sha256']);
  assert.equal(result.calls[0][1].p_owner_id, 'synthetic_b');
  assert.equal(result.calls[0][1].p_note_id, id);
});

test('seed-style IDs (non RFC4122 version/variant) are accepted as the same single note', async () => {
  const seed = 'a0000000-0000-0000-0000-000000000004';
  const result = await invoke({ url: '/api/restore/' + seed, data: { restored: true, noteId: seed, contentSha256: 'a'.repeat(64) } });
  assert.equal(result.res.code, 200);
  assert.equal(result.calls[0][1].p_note_id, seed);
});

test('missing or mismatched backup is refused, and no memo content is returned', async () => {
  assert.equal((await invoke({ data: { error: 'verified_backup_missing' } })).res.code, 409);
  assert.equal((await invoke({ data: { error: 'backup_verification_failed' } })).res.code, 409);
  assert.equal((await invoke({ data: { error: 'not_found_or_not_owned' } })).res.code, 404);
  assert.equal((await invoke()).res.body.title, undefined);
});
