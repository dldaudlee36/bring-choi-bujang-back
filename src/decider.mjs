import { getActiveDenyRules } from '../xdr/brute-force/decide.mjs';

// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny']);

export async function decide(request) {
  // XDR 차단 후보 거부 규칙 연결 (기존 규칙을 대체하지 않고 차단 대상 IP 우선 거부)
  try {
    const activeRules = getActiveDenyRules();
    const clientIp = request?.clientIp || request?.signals?.source;
    if (clientIp && activeRules.some(r => r.ip === clientIp)) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'xdr_ip_blocked',
        ruleIds: [RULE_IDS[0]],
      };
    }
  } catch {
    // 규칙 조회 실패 시 기존 판정기 규칙으로 안전 진행
  }

  // 판정기의 기존 규칙 유지
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [RULE_IDS[0]],
  };
}
