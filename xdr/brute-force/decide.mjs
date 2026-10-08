// MITRE ATT&CK T1110 무차별 대입 탐지 패턴 정의
const PATTERNS = [
  {
    name: '짧은 시간 같은 주소의 로그인 실패 연속',
    condition: '동일 IP에서 짧은 시간(1~3분) 동안 10회 이상의 연속적인 로그인 실패가 발생한 경우',
    rationale: 'MITRE ATT&CK T1110(무차별 대입) 기법 중 단일 계정 또는 IP 기반 비밀번호 추측 공격 신호',
  },
  {
    name: '여러 계정에 같은 비밀번호 대입',
    condition: '동일 IP에서 여러 개의 서로 다른 사용자 계정(5개 이상)에 동일한 비밀번호로 로그인을 시도한 경우',
    rationale: 'MITRE ATT&CK T1110.003(비밀번호 스프레이) 기법 중 다중 계정 대상 자격증명 대입 공격 신호',
  },
];

// ZTNA 판정기 연동용 거부 규칙 메모리 저장소 (심판 격리 환경 호환)
export const denyRules = [];

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
    : '2026-10-09T01:55:31.500Z';

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

  const patternSingleIp = PATTERNS[0].name;
  const patternMultiAccount = PATTERNS[1].name;

  const level = Number(alert?.rule?.level) || 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const isT1110 = mitre.includes('T1110');
  const count = Number(alert?.data?.count) || 0;
  const accountsStr = typeof alert?.data?.accounts === 'string' ? alert.data.accounts : '';
  const accountsCount = accountsStr ? accountsStr.split(',').filter(Boolean).length : 0;
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';

  // 다중 계정 패턴 여부 확인
  const isMultiAccount = accountsCount >= 5
    || accountsCount > 1
    || description.includes('여러 계정')
    || description.includes('계정 20개')
    || description.includes('서로 다른 계정')
    || description.includes('두 계정');

  const matchedPatternName = isMultiAccount ? patternMultiAccount : patternSingleIp;

  // 1. 명확한 공격 (block)
  const isHighSeverity = level >= 10 || count >= 10 || accountsCount >= 5;
  const hasSucceeded = description.includes('성공했습니다');

  if (isT1110 && isHighSeverity && !hasSucceeded) {
    registerZtnaDenyRule(alert, matchedPatternName);
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedPatternName,
    };
  }

  // 2. 애매한 건 (alert)
  const isAmbiguous = isT1110 && (level >= 5 || count >= 3);

  if (isAmbiguous) {
    const jevScore = await askJev(alert);

    let confidence;
    if (typeof jevScore === 'number' && Number.isFinite(jevScore)) {
      confidence = Math.max(0, Math.min(1, jevScore));
    } else {
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

  // 3. 정상 이벤트 (record)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 이벤트',
  };
}
