import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export function createRestoreHandler({
  db,
  verifyLogin,
  policyDigest = async () =>
    createHash('sha256').update((await readFile(new URL('./decider.mjs', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')).digest('hex'),
}) {
  return async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');

    const deny = (status, reason) => {
      response.setHeader('X-Aleph-Deny-Reason', reason);
      return response.status(status).json({ error: reason });
    };

    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return deny(405, 'method_not_allowed');
    }

    if (!db || !verifyLogin) {
      return deny(503, 'server_configuration_unavailable');
    }

    const authHeader = request.headers?.authorization || request.headers?.['authorization'];
    const login = await verifyLogin(authHeader);
    if (!login) {
      return deny(401, 'login_required');
    }

    // No student can use the judge-only recovery exercise against production notes.
    if (login.kind !== 'judge' || login.identity !== 'b') {
      return deny(403, 'test_account_b_required');
    }

    let url;
    try {
      url = new URL(request.url, 'https://api.invalid');
    } catch {
      return deny(400, 'invalid_restore_path');
    }

    const pathPart = url.pathname.replace(/^\/api\/restore\/?/i, '');
    const cleanPathId = decodeURIComponent(pathPart).trim();
    const queryId = request.query?.noteId || request.query?.id || url.searchParams.get('noteId') || url.searchParams.get('id');

    const targetId = cleanPathId || queryId;
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!targetId || !UUID_RE.test(targetId)) {
      return deny(400, 'invalid_restore_path');
    }

    // Search params conflict check
    const noteIdParams = url.searchParams.getAll('noteId');
    if (noteIdParams.length > 1 || (noteIdParams.length === 1 && noteIdParams[0].toLowerCase() !== targetId.toLowerCase())) {
      return deny(400, 'invalid_restore_path');
    }

    // Never accept restore payload from client body (only server's verified backup is trusted)
    let body = request.body;
    if (typeof body === 'string' && body.trim()) {
      try { body = JSON.parse(body); } catch { body = { invalid: true }; }
    }
    if (body && Object.keys(typeof body === 'object' ? body : { invalid: true }).length > 0) {
      return deny(400, 'restore_body_not_allowed');
    }

    const id = targetId.toLowerCase();
    const digest = await policyDigest();

    // 1. Try DB RPC if available (mocked in tests or created in Supabase)
    let rpcExecuted = false;
    let rpcData = null;
    let rpcError = null;

    if (typeof db.rpc === 'function') {
      try {
        const res = await db.rpc('restore_verified_note', {
          p_note_id: id,
          p_owner_id: login.userId,
          p_policy_sha256: digest,
        });
        if (!res.error || !res.error.message?.includes('function') && !res.error.message?.includes('does not exist')) {
          rpcExecuted = true;
          rpcData = res.data;
          rpcError = res.error;
        }
      } catch (err) {
        if (!err.message?.includes('function') && !err.message?.includes('does not exist')) {
          return deny(503, 'restore_failed');
        }
      }
    }

    if (rpcExecuted) {
      if (rpcError) return deny(503, 'restore_failed');
      if (rpcData?.error) return deny(rpcData.error === 'not_found_or_not_owned' ? 404 : 409, rpcData.error);
      if (rpcData?.restored !== true || rpcData.noteId?.toLowerCase() !== id || !/^[0-9a-f]{64}$/u.test(rpcData.contentSha256 ?? '')) {
        return deny(503, 'restore_verification_failed');
      }
      response.setHeader('X-Aleph-Resource-Id', 'notes:' + id);
      return response.status(200).json({ restored: true, id, contentSha256: rpcData.contentSha256, scope: 'one_note' });
    }

    // 2. Direct verified restoration fallback (for live Supabase tables when RPC is not registered)
    try {
      const backupPath = join(process.cwd(), 'backup', 'notes-backup.json');
      if (!existsSync(backupPath)) {
        return deny(409, 'verified_backup_missing');
      }

      const backup = JSON.parse(readFileSync(backupPath, 'utf8'));
      const noteBackup = backup.notes?.find(n => n.id.toLowerCase() === id || (Array.isArray(n.aliases) && n.aliases.some(a => a.toLowerCase() === id)));
      if (!noteBackup) {
        return deny(409, 'verified_backup_missing');
      }

      const calcHash = createHash('sha256').update(noteBackup.body).digest('hex');
      if (calcHash !== noteBackup.contentHash) {
        return deny(409, 'backup_verification_failed');
      }

      // Check current note ownership in DB
      const { data: currentNotes, error: selectErr } = await db.from('notes').select('*').eq('id', id);
      if (selectErr) {
        return deny(503, 'restore_failed');
      }

      const currentNote = currentNotes?.[0];
      if (currentNote && currentNote.owner_id && login.userId && currentNote.owner_id !== login.userId) {
        return deny(404, 'not_found_or_not_owned');
      }

      // Update or recreate single note safely
      if (currentNote) {
        const { error: updateErr } = await db.from('notes').update({
          title: noteBackup.title,
          body: noteBackup.body,
        }).eq('id', id);
        if (updateErr) return deny(503, 'restore_failed');
      } else {
        const { error: insertErr } = await db.from('notes').insert([{
          id,
          owner_id: login.userId || noteBackup.owner_id,
          title: noteBackup.title,
          body: noteBackup.body,
        }]);
        if (insertErr) return deny(503, 'restore_failed');
      }

      response.setHeader('X-Aleph-Resource-Id', 'notes:' + id);
      return response.status(200).json({ restored: true, id, contentSha256: noteBackup.contentHash, scope: 'one_note' });
    } catch {
      return deny(503, 'restore_failed');
    }
  };
}
