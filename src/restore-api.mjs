import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { trace, tokenHint } from './request-trace.mjs';

export function createRestoreHandler({ db, verifyLogin, policyDigest = async () =>
  createHash('sha256').update((await readFile(new URL('./decider.mjs', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')).digest('hex') }) {
  return async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    let who = null;
    let seenId = null;
    const deny = async (status, reason) => {
      if (who) await trace(db, { route: '/api/restore', method: request.method, ...who, noteId: seenId, status, reason });
      response.setHeader('X-Aleph-Deny-Reason', reason);
      return response.status(status).json({ error: reason });
    };
    if (request.method !== 'POST') { response.setHeader('Allow', 'POST'); return deny(405, 'method_not_allowed'); }
    if (!db || !verifyLogin) return deny(503, 'server_configuration_unavailable');
    const login = await verifyLogin(request.headers.authorization);
    if (!login) {
      await trace(db, { route: '/api/restore', method: request.method, kind: 'rejected', status: 401, reason: tokenHint(request.headers.authorization) });
      return deny(401, 'login_required');
    }
    who = { kind: login.kind, identity: login.identity ?? null, userId: login.userId };
    // No student can use the judge-only recovery exercise against production notes.
    if (login.kind !== 'judge' || login.identity !== 'b') return deny(403, 'test_account_b_required');
    let url;
    try { url = new URL(request.url, 'https://api.invalid'); } catch { return deny(400, 'invalid_restore_path'); }
    const match = /^\/api\/restore\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/iu.exec(url.pathname);
    if (!match || [...url.searchParams.keys()].some(key => key !== 'noteId')
      || url.searchParams.getAll('noteId').length > 1
      || url.searchParams.getAll('noteId').some(id => id.toLowerCase() !== match[1].toLowerCase()))
      return deny(400, 'invalid_restore_path');
    if (request.body && Object.keys(typeof request.body === 'object' ? request.body : { invalid: true }).length)
      return deny(400, 'restore_body_not_allowed');
    const id = match[1].toLowerCase();
    seenId = id;
    const digest = await policyDigest();
    const { data, error } = await db.rpc('restore_verified_note', {
      p_note_id: id, p_owner_id: login.userId, p_policy_sha256: digest,
    });
    if (error) return deny(503, 'restore_failed:' + String(error.code ?? error.message ?? '').slice(0, 40));
    if (data?.error) return deny(data.error === 'not_found_or_not_owned' ? 404 : 409, data.error);
    if (data?.restored !== true || data.noteId !== id || !/^[0-9a-f]{64}$/u.test(data.contentSha256 ?? ''))
      return deny(503, 'restore_verification_failed');
    await trace(db, { route: '/api/restore', method: request.method, ...who, noteId: id, status: 200, reason: 'restored' });
    response.setHeader('X-Aleph-Resource-Id', 'notes:' + id);
    return response.status(200).json({ restored: true, id, contentSha256: data.contentSha256, scope: 'one_note' });
  };
}
