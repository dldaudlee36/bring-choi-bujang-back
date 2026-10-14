import test from 'node:test';
import assert from 'node:assert/strict';
import { policyHash, previewPolicyRestore, applyTrialPolicyRestore, trialAllows } from '../src/trial-policy-restore.mjs';
import { createRestoreHandler, noteHash } from '../src/restore-api.mjs';

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
const B = 'synthetic_b';
const POLICY = 'b'.repeat(64);
const title = 'B memo';
const content = 'original bytes';
const goodBackup = () => ({ note_id: id, owner_id: B, title, content, content_sha256: noteHash(title, content),
  policy_sha256: POLICY, provenance: 'original_insert' });

// notes 표는 호출 순서대로 current(복구 전), after(복구 후)를 돌려준다.
async function invoke({
  login = { kind: 'judge', identity: 'b', userId: B },
  backup = goodBackup(),
  current = { id, owner_id: B },
  after = { id, owner_id: B, title, body: content, content },
  rpc = { restored: true, noteId: id, contentSha256: noteHash(title, content) },
  url = '/api/restore/' + id,
  body,
  method = 'POST',
} = {}) {
  const calls = { rpc: [], reads: [] };
  let noteReads = 0;
  const db = {
    from(table) {
      const q = { filters: {}, select() { return q; }, eq(k, v) { q.filters[k] = v; return q; },
        async maybeSingle() {
          calls.reads.push([table, { ...q.filters }]);
          if (table === 'note_restore_backups') {
            const ownerOk = backup && String(backup.owner_id) === String(q.filters.owner_id);
            return { data: ownerOk ? backup : null, error: null };
          }
          noteReads += 1;
          return { data: noteReads === 1 ? current : after, error: null };
        } };
      return q;
    },
    async rpc(name, args) { calls.rpc.push([name, args]); return { data: rpc, error: null }; },
  };
  const res = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await createRestoreHandler({ db, verifyLogin: async () => login, policyDigest: async () => POLICY })(
    { method, url, body, headers: {} }, res);
  return { res, calls };
}

test('restore reads the owned copy, re-verifies it, restores one note, and re-reads ID/owner/hash', async () => {
  const result = await invoke();
  assert.equal(result.res.code, 200);
  assert.equal(result.res.body.contentSha256, noteHash(title, content));
  assert.equal(result.res.body.state, 'reverted');
  assert.deepEqual(result.calls.rpc[0][1], { p_note_id: id, p_owner_id: B, p_policy_sha256: POLICY });
  // 사본 읽기 → 현재 소유자 확인 → (RPC) → 복원 후 다시 읽기
  assert.deepEqual(result.calls.reads.map(r => r[0]), ['note_restore_backups', 'notes', 'notes']);
  assert.equal(result.calls.reads[0][1].owner_id, B);
});

test('a deleted note is recreated from the copy', async () => {
  const result = await invoke({ current: null });
  assert.equal(result.res.code, 200);
  assert.equal(result.res.body.state, 'recreated');
});

test('only judge B is accepted, and client owner/content/body/query values are never used', async () => {
  for (const options of [
    { login: null },
    { login: { kind: 'student', identity: 'b', userId: B } },
    { login: { kind: 'judge', identity: 'a', userId: 'synthetic_a' } },
    { url: '/api/restore/' + id + '?noteId=other' },
  ]) {
    const denied = await invoke(options);
    assert.notEqual(denied.res.code, 200);
    assert.equal(denied.calls.rpc.length, 0);
  }
  const result = await invoke({ body: { owner_id: 'other', title: 'replacement', content: 'evil' }, url: '/api/restore/' + id + '?x=1&owner=other' });
  assert.equal(result.res.code, 200);
  assert.deepEqual(Object.keys(result.calls.rpc[0][1]).sort(), ['p_note_id', 'p_owner_id', 'p_policy_sha256']);
  assert.equal(result.calls.rpc[0][1].p_owner_id, B);
});

test('restoreRoute POST /api/notes/:id/restore and seed-style IDs reach the same single-note restore', async () => {
  assert.equal((await invoke({ url: '/api/notes/' + id + '/restore?id=' + id })).res.code, 200);
  const plain = await invoke({ url: '/api/notes/' + id });
  assert.equal(plain.res.code, 400);
  assert.equal(plain.calls.rpc.length, 0);
  const seed = 'a0000000-0000-0000-0000-000000000004';
  const backup = { ...goodBackup(), note_id: seed };
  const result = await invoke({ url: '/api/restore/' + seed, backup,
    current: { id: seed, owner_id: B }, after: { id: seed, owner_id: B, title, body: content, content },
    rpc: { restored: true, noteId: seed, contentSha256: noteHash(title, content) } });
  assert.equal(result.res.code, 200);
  assert.equal(result.calls.rpc[0][1].p_note_id, seed);
});

test('missing, foreign, or tampered copies stop before any restore', async () => {
  const missing = await invoke({ backup: null });
  assert.equal(missing.res.code, 404);
  assert.equal(missing.calls.rpc.length, 0);
  const foreign = await invoke({ backup: { ...goodBackup(), owner_id: 'synthetic_a' } });
  assert.equal(foreign.res.code, 404);
  assert.equal(foreign.calls.rpc.length, 0);
  for (const bad of [
    { ...goodBackup(), content: 'tampered copy' },
    { ...goodBackup(), content_sha256: '0'.repeat(64) },
    { ...goodBackup(), policy_sha256: 'c'.repeat(64) },
    { ...goodBackup(), provenance: 'unknown' },
  ]) {
    const r = await invoke({ backup: bad });
    assert.equal(r.res.code, 409);
    assert.equal(r.res.headers['X-Aleph-Deny-Reason'], 'backup_unverified');
    assert.equal(r.calls.rpc.length, 0);
  }
  const other = await invoke({ current: { id, owner_id: 'synthetic_a' } });
  assert.equal(other.res.code, 404);
  assert.equal(other.calls.rpc.length, 0);
});

test('a restored note whose ID, owner, or hash differs from the copy is reported as a mismatch', async () => {
  for (const after of [
    { id, owner_id: B, title, body: 'different', content: 'different' },
    { id, owner_id: 'synthetic_a', title, body: content, content },
    null,
  ]) {
    const r = await invoke({ after });
    assert.equal(r.res.code, 409);
    assert.equal(r.res.headers['X-Aleph-Deny-Reason'], 'restore_mismatch');
  }
  assert.equal((await invoke({ rpc: { restored: true, noteId: id, contentSha256: 'a'.repeat(64) } })).res.code, 409);
  assert.equal((await invoke({ rpc: { error: 'backup_verification_failed' } })).res.code, 409);
  assert.equal((await invoke({ rpc: { error: 'not_found_or_not_owned' } })).res.code, 404);
  assert.equal((await invoke()).res.body.title, undefined);
});
