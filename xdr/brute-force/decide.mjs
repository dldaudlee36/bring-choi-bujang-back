import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PATTERNS_PATH = join(dirname(fileURLToPath(import.meta.url)), 'patterns.json');

let cachedPatterns = null;

async function loadPatterns() {
  if (cachedPatterns) return cachedPatterns;
  try {
    const raw = await readFile(PATTERNS_PATH, 'utf8');
    cachedPatterns = JSON.parse(raw);
  } catch {
    cachedPatterns = [
      { name: '짧은 시간 같은 주소의 로그인 실패 연속' },
      { name: '여러 계정에 같은 비밀번호 대입' },
    ];
  }
  return cachedPatterns;
}

/**
 * 애매한 경보에 대해 Jev AI에게 추가 평가 요청
 * Jev가 응답하지 않거나 설정되지 않은 경우 null을 반환하여 기본 alert로 떨어지도록 함
 */
async function askJev(alert) {
  try {
    if (typeof globalThis.jev?.evaluate === 'function') {
      const score = await globalThis.jev.evaluate(alert);
      if (typeof score === 'number' && Number.isFinite(score)) return score;
    }
    if (typeof process !== 'undefined' && process.env?.JEV_API_URL) {
      const res = await fetch(process.env.JEV_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert),
        signal: AbortSignal.timeout(1500),
      });
      if (res.ok) {
        const data = await res.json();
        const score = Number(data?.confidence);
        if (Number.isFinite(score)) return score;
      }
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
 */
export async function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효하지 않은 경보' };
  }

  const patterns = await loadPatterns();
  const patternSingleIp = patterns[0]?.name || '짧은 시간 같은 주소의 로그인 실패 연속';
  const patternMultiAccount = patterns[1]?.name || '여러 계정에 같은 비밀번호 대입';

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
  // T1110 기법이면서 심각도 10 이상 또는 대량 실패(10건 이상) 또는 다중 계정 대입(5개 이상)
  // 성공 이력이 없는 순수 대량 공격인 경우
  const isHighSeverity = level >= 10 || count >= 10 || accountsCount >= 5;
  const hasSucceeded = description.includes('성공했습니다');

  if (isT1110 && isHighSeverity && !hasSucceeded) {
    const confidence = 0.95; // 0.85 이상 -> block
    return {
      action: 'block',
      confidence,
      reason: matchedPatternName,
    };
  }

  // 2. 애매한 건 (alert)
  // T1110 관련 경보이나 소수 실패 후 성공, 비밀번호 변경 실패, 위치 이상 등 판단이 필요한 경우
  const isAmbiguous = isT1110 && (level >= 5 || count >= 3);

  if (isAmbiguous) {
    const jevScore = await askJev(alert);

    let confidence;
    if (typeof jevScore === 'number' && Number.isFinite(jevScore)) {
      confidence = Math.max(0, Math.min(1, jevScore));
    } else {
      // Jev가 응답하지 않으면 기본 alert(0.6)로 떨어짐
      confidence = 0.6;
    }

    let action = 'alert';
    if (confidence >= 0.85) {
      action = 'block';
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
  // T1110 미포함, 낮은 레벨(level < 5), 정상 로그인/로그아웃/세션 확인 등
  const confidence = 0.1; // 0.5 미만 -> record
  return {
    action: 'record',
    confidence,
    reason: '정상 이벤트',
  };
}
