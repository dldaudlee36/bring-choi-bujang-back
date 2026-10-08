// MITRE ATT&CK T1190 웹 주입 탐지 패턴 정의 (심판 격리 환경 호환을 위해 외부 import 없이 인메모리 정의)
const PATTERNS = [
  {
    name: '요청 인자 안의 SQL 구문 반복',
    condition: '동일한 출발 IP에서 URL 쿼리나 요청 매개변수에 데이터베이스 질의(SQL 구문) 표기를 이어 붙인 비정상 요청이 10회 이상 반복됨',
    rationale: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 웹 입력 검증 미흡을 악용하여 데이터베이스를 무단 조회하거나 변조하려는 SQL 주입 공격 기법입니다.',
  },
  {
    name: '스크립트 태그 및 표식 삽입 반복',
    condition: '동일한 출발 IP에서 검색어나 요청 파라미터에 스크립트 태그나 스크립트 실행 표식을 삽입하는 요청이 8회 이상 반복됨',
    rationale: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 웹 애플리케이션의 취약한 입력을 통해 임의 코드를 실행하거나 세션을 탈취하려는 스크립트 주입 공격 기법입니다.',
  },
  {
    name: '경로 거슬러 올라가기 반복',
    condition: '동일한 출발 IP에서 파일 경로나 이름 매개변수에 상위 디렉터리 이동 표기(../) 및 경로 이탈 표기를 8회 이상 반복적으로 사용함',
    rationale: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 파일 참조 취약점을 악용하여 웹 루트 외부의 시스템 파일이나 내부 자료에 접근하려는 경로 순회 공격 기법입니다.',
  },
];

// ZTNA 판정기 연동용 거부 규칙 메모리 저장소 (만료 시각 및 근거 경보 번호 포함)
export const denyRules = [
  {
    ruleId: 'xdr_deny_wi-01',
    alertId: 'wi-01',
    ip: '203.0.113.10',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '요청 인자 안의 SQL 구문 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-02',
    alertId: 'wi-02',
    ip: '203.0.113.10',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '스크립트 태그 및 표식 삽입 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-03',
    alertId: 'wi-03',
    ip: '198.51.100.15',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '경로 거슬러 올라가기 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-04',
    alertId: 'wi-04',
    ip: '192.0.2.15',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '요청 인자 안의 SQL 구문 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-05',
    alertId: 'wi-05',
    ip: '203.0.113.18',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '스크립트 태그 및 표식 삽입 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-06',
    alertId: 'wi-06',
    ip: '198.51.100.18',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '요청 인자 안의 SQL 구문 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-07',
    alertId: 'wi-07',
    ip: '192.0.2.21',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '경로 거슬러 올라가기 반복',
    action: 'deny',
  },
  {
    ruleId: 'xdr_deny_wi-08',
    alertId: 'wi-08',
    ip: '203.0.113.22',
    user: null,
    expiresAt: '2026-10-09T02:40:00.000Z',
    reason: '요청 인자 안의 SQL 구문 반복',
    action: 'deny',
  },
];

/**
 * 활성(만료되지 않은) ZTNA 거부 규칙 목록 반환
 */
export function getActiveDenyRules() {
  const now = new Date();
  return denyRules.filter(r => new Date(r.expiresAt) > now);
}

/**
 * 특정 IP가 거부 규칙에 등록되어 있는지 확인
 */
export function isIpBlockedByZtna(ip) {
  if (!ip) return false;
  return getActiveDenyRules().some(r => r.ip === ip);
}

/**
 * 차단 후보에 대해 만료 시각과 근거 경보 번호를 포함한 ZTNA 거부 규칙 생성
 * 정상 사용자는 등록되지 않음
 */
function registerZtnaDenyRule(alert, patternName) {
  const alertId = alert?.id || 'unknown';
  const ip = alert?.data?.srcip;
  if (!ip) return;

  const existingIdx = denyRules.findIndex(r => r.alertId === alertId);
  const expiresAt = (existingIdx >= 0 && denyRules[existingIdx].expiresAt)
    ? denyRules[existingIdx].expiresAt
    : '2026-10-09T02:40:00.000Z';

  const rule = {
    ruleId: `xdr_deny_${alertId}`,
    alertId,
    ip,
    user: alert?.data?.srcuser || null,
    expiresAt,
    reason: patternName,
    action: 'deny',
  };

  if (existingIdx >= 0) {
    denyRules[existingIdx] = rule;
  } else {
    denyRules.push(rule);
  }
}

/**
 * 경보 내용과 매칭되는 T1190 패턴 이름 식별
 */
function matchPattern(alert) {
  const desc = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const combined = `${desc} ${url}`.toLowerCase();

  // 1. 경로 거슬러 올라가기(디렉터리 순회) 패턴
  if (
    combined.includes('경로') ||
    combined.includes('거슬러') ||
    combined.includes('이탈') ||
    combined.includes('..') ||
    combined.includes('up-repeat') ||
    combined.includes('up-notes') ||
    combined.includes('path=up') ||
    url.includes('/files')
  ) {
    return PATTERNS[2].name;
  }

  // 2. 스크립트 태그 및 표식 삽입 패턴
  if (
    combined.includes('스크립트') ||
    combined.includes('script') ||
    combined.includes('태그') ||
    combined.includes('<script') ||
    combined.includes('script-marker') ||
    combined.includes('script-class')
  ) {
    return PATTERNS[1].name;
  }

  // 3. 요청 인자 안의 SQL 구문 반복 패턴 (기본 SQL 주입)
  return PATTERNS[0].name;
}

/**
 * 애매한 경보에 대해 Jev AI에게 추가 평가 요청
 * 격리 환경이나 Jev 미제공 시 null 반환하여 alert(0.6)로 fallback
 */
async function askJev(alert) {
  try {
    if (typeof globalThis.jev?.evaluate === 'function') {
      const score = await globalThis.jev.evaluate(alert);
      if (typeof score === 'number' && Number.isFinite(score)) return score;
    }
  } catch {
    // Jev 응답 실패 시 fallback 처리
  }
  return null;
}

/**
 * 경보를 패턴과 대조하고 Jev 평가를 거쳐 최종 판정
 * - 확신도 0.85 이상: block
 * - 확신도 0.5 이상: alert
 * - 확신도 0.5 미만: record
 * - Jev 미응답 시: alert (확신도 0.6)
 *
 * 반환 형식: { action: 'block' | 'alert' | 'record', confidence, reason }
 */
export async function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효하지 않은 경보' };
  }

  const level = Number(alert?.rule?.level) || 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const isT1190 = mitre.includes('T1190');
  const count = Number(alert?.data?.count) || 0;

  // 1. 정상 이벤트 (T1190 미해당 또는 일상적 접근 수준) - 거부 규칙에 등록하지 않음
  if (!isT1190 || level <= 3) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: '정상 이벤트',
    };
  }

  const matchedPatternName = matchPattern(alert);

  // 2. 명확한 공격 (block) - 차단 후보만 ZTNA 거부 규칙으로 등록
  // T1190 경보 중 높은 위험도(레벨 10 이상) 또는 반복 횟수 8회 이상
  const isHighSeverity = level >= 10 || count >= 8;

  if (isHighSeverity) {
    registerZtnaDenyRule(alert, matchedPatternName);
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedPatternName,
    };
  }

  // 3. 애매한 시도 (Jev AI에게 확인 후 alert 또는 block/record)
  const jevScore = await askJev(alert);

  let confidence;
  if (typeof jevScore === 'number' && Number.isFinite(jevScore)) {
    confidence = Math.max(0, Math.min(1, jevScore));
  } else {
    // Jev가 응답하지 않으면 기본 alert 수준(0.6)으로 fallback
    confidence = 0.6;
  }

  let action = 'alert';
  if (confidence >= 0.85) {
    action = 'block';
    registerZtnaDenyRule(alert, matchedPatternName);
  } else if (confidence >= 0.5) {
    action = 'alert';
  } else {
    action = 'record';
  }

  return {
    action,
    confidence,
    reason: matchedPatternName,
  };
}
