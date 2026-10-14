import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { trace, tokenHint, entryHint } from './request-trace.mjs';

// 내용 지문: sha256(UTF-8 '제목바이트수:제목본문'). DB 함수(db/verified-single-note-restore.sql)와 같은 방식이다.
export function noteHash(title, content) {
  const t = String(title);
  return createHash('sha256').update(`${Buffer.byteLength(t, 'utf8')}:${t}${String(content)}`, 'utf8').digest('hex');
}
const sameId = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
const TRUSTED_ORIGINS = ['original_insert', 'baseline_verified'];

export function createRestoreHandler({ db, verifyLogin, policyDigest = async () =>
  createHash('sha256').update((await readFile(new URL('./decider.mjs', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')).digest('hex') }) {
  return async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    await trace(db, { route: '/api/restore', method: request.method, kind: 'entry', reason: entryHint(request) });
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
    const match = new RegExp('^/api/restore/' + '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})' + '$', 'iu').exec(url.pathname)
      ?? new RegExp('^/api/notes/' + '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})' + '/restore$', 'iu').exec(url.pathname);
    // 경로의 ID만 신뢰한다. 쿼리의 noteId가 경로와 다르면 거부하고, 그 밖의 쿼리와 요청 본문은 읽지 않고 무시한다.
    if (!match || url.searchParams.getAll('noteId').length > 1
      || url.searchParams.getAll('noteId').some(id => id.toLowerCase() !== match[1].toLowerCase()))
      return deny(400, 'invalid_restore_path');
    const id = match[1].toLowerCase();
    seenId = id;
    const owner = login.userId;

    // 1) 본인 소유의 검증 사본을 직접 읽는다. 없거나 남의 것이면 404로 멈춘다.
    const { data: backup, error: backupError } = await db.from('note_restore_backups')
      .select('note_id, owner_id, title, content, content_sha256, policy_sha256, provenance')
      .eq('note_id', id).eq('owner_id', owner).maybeSingle();
    if (backupError) return deny(503, 'backup_read_failed');
    if (!backup || !sameId(backup.note_id, id) || !sameId(backup.owner_id, owner)) return deny(404, 'verified_backup_missing');

    // 2) 사본의 지문과 정책 지문을 다시 계산해 대조한다. 하나라도 다르면 복구하지 않는다.
    const digest = await policyDigest();
    const expected = noteHash(backup.title, backup.content);
    if (expected !== backup.content_sha256 || backup.policy_sha256 !== digest
      || !TRUSTED_ORIGINS.includes(backup.provenance)) return deny(409, 'backup_unverified');

    // 3) 지금 그 메모가 다른 사람 것이면 건드리지 않는다.
    const { data: current, error: currentError } = await db.from('notes').select('id, owner_id').eq('id', id).maybeSingle();
    if (currentError) return deny(503, 'current_read_failed');
    if (current && !sameId(current.owner_id, owner)) return deny(404, 'not_found_or_not_owned');
    const previousState = current ? 'reverted' : 'recreated';

    // 4) 한 건만 복원한다. DB 함수가 같은 검증을 한 번 더 하고, 잠금 안에서 복원과 감사 기록을 처리한다.
    const { data, error } = await db.rpc('restore_verified_note', {
      p_note_id: id, p_owner_id: owner, p_policy_sha256: digest,
    });
    if (error) return deny(503, 'restore_failed:' + String(error.code ?? error.message ?? '').slice(0, 40));
    if (data?.error) return deny(data.error === 'verified_backup_missing' || data.error === 'not_found_or_not_owned' ? 404 : 409, data.error);
    if (data?.restored !== true || !sameId(data.noteId, id) || data.contentSha256 !== expected) return deny(409, 'restore_mismatch');

    // 5) 복원한 메모를 다시 읽어 ID, 소유자, 내용 지문이 사본과 같은지 확인한다.
    const { data: after, error: afterError } = await db.from('notes').select('id, owner_id, title, body, content').eq('id', id).maybeSingle();
    if (afterError || !after || !sameId(after.id, id) || !sameId(after.owner_id, backup.owner_id)
      || noteHash(after.title, after.content ?? after.body ?? '') !== expected) return deny(409, 'restore_mismatch');

    await trace(db, { route: '/api/restore', method: request.method, ...who, noteId: id, status: 200, reason: 'restored' });
    response.setHeader('X-Aleph-Resource-Id', 'notes:' + id);
    return response.status(200).json({ restored: true, state: previousState, id, owner: 'self',
      contentSha256: expected, scope: 'one_note' });
  };
}
