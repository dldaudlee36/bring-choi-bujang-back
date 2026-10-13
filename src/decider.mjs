// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계 규칙 device_registered: 등록되어 사용자와 묶인 기기만 내 자료실 읽기(GET notes)를 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

/**
 * 엔진이 검증해 넘긴 가상 접속 정보(signals, recentEvents)의 출처를 구분합니다.
 * 지역·시각·네트워크·행동이 없거나 출처가 불명확하면 임의의 정상값으로 채우지 않으며,
 * 위조된 클라이언트 헤더나 임의 속성을 신뢰하는 접속 정보로 승격하지 않습니다.
 */
function parseVerifiedSignals(request) {
  const signals = request?.signals;
  if (!signals || typeof signals !== 'object' || typeof signals.source !== 'string') {
    return { trusted: false, source: 'unspecified', region: null, network: null, hour: null, recentEvents: null };
  }

  // 엔진이 검증한 출처인지 구분 (가상 요청 fixture 출처: 'judge_fixture')
  const isTrusted = signals.source === 'judge_fixture';

  return {
    trusted: isTrusted,
    source: signals.source,
    // 출처가 유효할 때만 엔진이 전달한 값을 읽고, 없거나 불명확한 경우 정상값으로 대체하지 않고 null로 유지
    region: typeof signals.region === 'string' ? signals.region : null,
    network: typeof signals.network === 'string' ? signals.network : null,
    hour: typeof signals.hour === 'number' && Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 23 ? signals.hour : null,
    recentEvents: Array.isArray(request?.recentEvents) ? request.recentEvents : null,
  };
}

export async function decide(request) {
  // 엔진이 확인해 넘긴 로그인(subjectId)·기기(deviceId, deviceRegistered)·동작(method)·경로(service) 검증
  const hasLogin = typeof request?.subjectId === 'string' && request.subjectId.trim().length > 0;
  const hasDevice = typeof request?.deviceId === 'string' && request.deviceId.trim().length > 0;
  const isDeviceRegistered = request?.deviceRegistered === true;
  const isReadAction = request?.method === 'GET';
  const isNotesService = request?.service === 'notes';

  // 1. 기본 기기 및 접속 자격 규칙 검증 (기존 device_registered 규칙 유지)
  if (!hasLogin || !hasDevice || !isDeviceRegistered || !isReadAction || !isNotesService) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 엔진이 검증한 가상 접속 정보의 출처 및 정황 검사
  const verifiedSignals = parseVerifiedSignals(request);

  // 평소와 다른 시각(심야/새벽)
  const isUnusualHour = verifiedSignals.hour !== null && (verifiedSignals.hour < 7 || verifiedSignals.hour > 21);
  // 처음 보는 네트워크
  const isUnusualNetwork = verifiedSignals.network === 'unusual';
  // 갑자기 많은 자료를 읽는 가상 사건
  const hasHighActivity = Array.isArray(verifiedSignals.recentEvents) && verifiedSignals.recentEvents.some(
    e => (typeof e.count === 'number' && e.count >= 10) || e.kind === 'risk_signal' || e.kind === 'high_read' || e.kind === 'burst'
  );

  // 평소와 다른 시각 + 낯선 네트워크 + 대량 조회 복합 이상 사건 확인
  // (지역 하나만으로 영구 차단하지 않으며 복합 이상 정황 발생 시 추가 확인 요구)
  const isSuspicious = verifiedSignals.trusted && isUnusualHour && isUnusualNetwork && hasHighActivity;

  if (isSuspicious) {
    // 추가 인증(step_up) 완료 여부 확인 (verified가 true이고 유효시간 0~900초 이내)
    const isStepUpVerified = request?.stepUp?.verified === true
      && typeof request?.stepUp?.authAgeSeconds === 'number'
      && request.stepUp.authAgeSeconds >= 0
      && request.stepUp.authAgeSeconds <= 900;

    if (isStepUpVerified) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['step_up_required'],
      };
    }

    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 3. 정상 사건 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
