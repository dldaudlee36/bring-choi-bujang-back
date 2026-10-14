// 심판 요청 관찰용 기록. 토큰, 본문, 메모 내용은 저장하지 않는다. 실패해도 요청 처리에는 영향이 없다.
export async function trace(db, entry) {
  try {
    if (!db || typeof db.from !== 'function') return;
    await db.from('judge_request_trace').insert({
      route: String(entry.route ?? '').slice(0, 120),
      method: String(entry.method ?? '').slice(0, 10),
      login_kind: entry.kind ?? null,
      identity: entry.identity ?? null,
      user_id: entry.userId ?? null,
      note_id: entry.noteId ?? null,
      status: Number.isInteger(entry.status) ? entry.status : null,
      reason: entry.reason ? String(entry.reason).slice(0, 80) : null,
    });
  } catch { /* 기록 실패는 무시 */ }
}
