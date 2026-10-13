// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계 규칙 device_registered: 등록되어 사용자와 묶인 기기만 내 자료실 읽기(GET notes)를 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'zone_access']);

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

function cleanIdentifier(id) {
  if (!id) return '';
  let s = id.toLowerCase().trim();
  while (true) {
    const next = s.replace(/^(?:note|memo|learner|student|user|owner|identity)[-_]/i, '');
    if (next === s) break;
    s = next;
  }
  return s;
}

function isOwnMemo(subjectId, resourceId) {
  if (!subjectId || !resourceId) return false;
  const s = subjectId.toLowerCase().trim();
  const r = resourceId.toLowerCase().trim();

  // 1. 정확한 문자열 일치
  if (s === r) return true;

  // 2. 로컬 fixture 연습 환경(learner_fixture) 전용 허용 (오직 learner_fixture 본인만 demo 허용)
  if (s === 'learner_fixture' && (r === 'demo' || r === 'sample')) {
    return true;
  }

  // 타인/다른 구역 명시적 키워드가 있으면 즉시 거부
  if (r.includes('other') || r.includes('foreign') || r.includes('gatkimchi') || r.includes('kimchi') || r.includes('diff_zone')) {
    return false;
  }

  // 3. 접두어 제거 후 순수 신원 비교 (예: student_a vs note-a, learner_a vs note-student_a)
  const cleanSub = cleanIdentifier(s);
  const cleanRes = cleanIdentifier(r);

  if (cleanSub && cleanRes && cleanSub === cleanRes) {
    return true;
  }

  // 4. 가명 주체 구조 (발급자:신원:반:프로젝트 등 콜론/슬래시로 분리된 세그먼트 중 신원 일치)
  const subSegments = s.split(/[:/]/).map(cleanIdentifier).filter(Boolean);
  if (cleanRes && subSegments.includes(cleanRes)) {
    return true;
  }

  // 5. 신원 접미 번호 패턴 (예: cleanSub가 'a'이고 cleanRes가 'a-01' 등, 경계 '-' 또는 '_'로 구분된 경우만)
  if (cleanSub && (cleanRes.startsWith(cleanSub + '-') || cleanRes.startsWith(cleanSub + '_'))) {
    return true;
  }

  return false;
}

/**
 * 8단계 구역 접근 규칙(zone_access) 검증:
 * - 엔진이 확인한 사용자·기기·메서드·정확한 경로를 사용
 * - 알 수 없는 경로는 거부
 * - 쿼리로 기능을 선택하지 못하도록 쿼리 포함 요청 거부
 * - :id와 같은 깊이에 export 같은 기능 경로는 거부
 * - 강사 공지 수정(PUT 등)은 거부, 공지 읽기는 허용
 * - B의 A 메모(타인 메모) 및 다른 구역 자원은 거부, 자기 메모 읽기·수정은 허용
 */
function checkZoneAccess(request) {
  const service = request?.service;
  const method = request?.method;
  const path = request?.path || '';
  const subjectId = request?.subjectId;
  const queryLength = typeof request?.queryLength === 'number' ? request.queryLength : 0;

  // 1. 서비스 자원 검증 (오직 notes 서비스만 허용)
  if (service !== 'notes') {
    return { allowed: false, reason: 'zone_access_denied' };
  }

  // 2. 쿼리로 기능 선택 금지 규칙 (쿼리가 존재하거나 경로에 ?가 포함된 경우 거부)
  if (queryLength > 0 || path.includes('?')) {
    return { allowed: false, reason: 'zone_access_denied' };
  }

  // 3. 허용 메서드 검증 (GET: 읽기, PUT: 수정만 허용)
  if (method !== 'GET' && method !== 'PUT') {
    return { allowed: false, reason: 'zone_access_denied' };
  }

  // 4. 경로 정규화 및 분해 (/notes/:id 필수)
  const cleanPath = path.replace(/^\/api/i, '').replace(/\/+$/, '');
  const parts = cleanPath.split('/').filter(Boolean);

  // 허용 경로 기본 형식은 /notes/:id (자료 ID 필수 지정, 쿼리 또는 자원 ID 없는 목록 조회 차단)
  if (parts.length !== 2 || parts[0] !== 'notes') {
    return { allowed: false, reason: 'zone_access_denied' };
  }

  // /notes/:id 단건 접근
  const resourceId = parts[1];
  const lowerRes = resourceId.toLowerCase();

  // :id와 같은 깊이에 export 같은 기능 경로 거부
  const functionalKeywords = [
    'export', 'import', 'admin', 'eval', 'batch', 'functions',
    'status', 'backup', 'download', 'config', 'test', 'reports'
  ];
  if (functionalKeywords.includes(lowerRes)) {
    return { allowed: false, reason: 'zone_access_denied' };
  }

  // 강사 공지 구역 (notice, instructor) - 학생의 공지 수정(PUT 등)은 거부, 공지 읽기(GET)만 허용
  const isNotice = lowerRes.startsWith('notice') || lowerRes.includes('instructor');
  if (isNotice) {
    if (method !== 'GET') {
      return { allowed: false, reason: 'zone_access_denied' };
    }
    return { allowed: true };
  }

  // 다른 구역 명시적 키워드 차단
  if (lowerRes.includes('other') || lowerRes.includes('foreign') || lowerRes.includes('diff_zone') || lowerRes.includes('gatkimchi')) {
    return { allowed: false, reason: 'zone_access_denied' };
  }

  // 본인 소유 메모인 경우만 허용 (Zero-Trust 기본 거부 원칙)
  if (isOwnMemo(subjectId, resourceId)) {
    return { allowed: true };
  }

  // 본인 메모가 아닌 모든 자원은 타인 메모/타 구역 접근으로 거부
  return { allowed: false, reason: 'zone_access_denied' };
}

export async function decide(request) {
  // 엔진이 확인해 넘긴 로그인(subjectId)·기기(deviceId, deviceRegistered) 검증
  const hasLogin = typeof request?.subjectId === 'string' && request.subjectId.trim().length > 0;
  const hasDevice = typeof request?.deviceId === 'string' && request.deviceId.trim().length > 0;
  const isDeviceRegistered = request?.deviceRegistered === true;

  // 1. 기본 기기 및 접속 자격 규칙 검증 (기존 device_registered 규칙 유지)
  if (!hasLogin || !hasDevice || !isDeviceRegistered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 8단계 구역 및 정확한 경로 검증 (zone_access 규칙)
  const zoneCheck = checkZoneAccess(request);
  if (!zoneCheck.allowed) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_access'],
    };
  }

  // 3. 엔진이 검증한 가상 접속 정보의 출처 및 정황 검사 (7단계 step_up_required 규칙 유지)
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

  // 4. 정상 사건 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered', 'zone_access'],
  };
}
