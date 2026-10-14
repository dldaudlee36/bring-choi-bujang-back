import { decodeJwt, decodeProtectedHeader } from 'jose';

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
      reason: entry.reason ? String(entry.reason).slice(0, 240) : null,
    });
  } catch { /* 기록 실패는 무시 */ }
}

// 검증 전 토큰의 공개 클레임(발급자, 대상, 알고리즘, 만료)만 요약한다. 서명 전체나 토큰 원문은 저장하지 않는다.
export function tokenHint(authorization) {
  try {
    const token = String(authorization ?? '').replace(/^Bearer /, '');
    if (!token) return 'no_token';
    const c = decodeJwt(token);
    const h = decodeProtectedHeader(token);
    const now = Math.floor(Date.now() / 1000);
    return `iss=${String(c.iss).slice(0, 70)} aud=${JSON.stringify(c.aud)?.slice(0, 80)} alg=${h.alg} role=${c.aleph_role ?? '-'} id=${c.aleph_identity ?? '-'} exp_in=${(c.exp ?? 0) - now}s`;
  } catch { return 'undecodable_token'; }
}

// 모든 요청의 진입 기록. 토큰과 본문은 제외하고 메서드, 경로, 인증 헤더 유무, 호스트, 클라이언트 종류만 남긴다.
export function entryHint(request) {
  const h = request.headers ?? {};
  return `url=${String(request.url ?? '').slice(0, 110)} auth=${Boolean(h.authorization)} host=${String(h.host ?? '').slice(0, 60)} ua=${String(h['user-agent'] ?? '').slice(0, 40)}`;
}
