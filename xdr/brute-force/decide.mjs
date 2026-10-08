import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '..', '..');
const PATTERNS_PATH = join(__dirname, 'patterns.json');
const ALERTS_LOG_PATH = join(ROOT_DIR, 'xdr', 'alerts.log');
const DENY_RULES_PATH = join(ROOT_DIR, 'xdr', 'deny-rules.json');

let cachedPatterns = null;
export const denyRules = [];

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
 * 활성(만료되지 않은) ZTNA 거부 규칙 목록 반환 (메모리 또는 디스크 캐시)
 */
export function getActiveDenyRules() {
  const now = new Date();
  if (denyRules.length === 0) {
    try {
      const raw = readFileSync(DENY_RULES_PATH, 'utf8');
      const loaded = JSON.parse(raw);
      if (Array.isArray(loaded)) {
        denyRules.push(...loaded);
      }
    } catch {
      // 파일 미존재 시 무시
    }
  }
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
 * 차단 후보에 대해 만료 시각과 근거 경보 번호를 포함한 ZTNA 거부 규칙 생성 및 저장
 * 정상 사용자는 등록되지 않음
 */
async function registerZtnaDenyRule(alert, patternName) {
  const alertId = alert?.id || 'unknown';
  const ip = alert?.data?.srcip;
  if (!ip) return;

  // 만료 시각: 24시간 뒤
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const rule = {
    ruleId: `xdr_deny_${alertId}`,
    alertId,
    ip,
    user: alert?.data?.srcuser || null,
    expiresAt,
    reason: patternName,
    action: 'deny',
  };

  const existingIdx = denyRules.findIndex(r => r.alertId === alertId);
  if (existingIdx >= 0) {
    denyRules[existingIdx] = rule;
  } else {
    denyRules.push(rule);
  }

  try {
    await mkdir(dirname(DENY_RULES_PATH), { recursive: true });
    await writeFile(DENY_RULES_PATH, `${JSON.stringify(denyRules, null, 2)}\n`, 'utf8');
  } catch {
    // 영속화 실패 방어
  }
}

/**
 * 애매한 경보 발생 시 xdr/alerts.log에 한 줄씩 기록
 */
async function recordAlertLog(alert, patternName) {
  const timestamp = alert?.timestamp || new Date().toISOString();
  const alertId = alert?.id || 'unknown';
  const ip = alert?.data?.srcip || '-';
  const user = alert?.data?.srcuser || '-';
  const line = `${timestamp} [ALERT] id=${alertId} ip=${ip} user=${user} reason="${patternName}"\n`;

  try {
    await mkdir(dirname(ALERTS_LOG_PATH), { recursive: true });
    let existing = '';
    try {
      existing = await readFile(ALERTS_LOG_PATH, 'utf8');
    } catch {
      // 파일 미존재
    }
    if (!existing.includes(`id=${alertId} `)) {
      await appendFile(ALERTS_LOG_PATH, line, 'utf8');
    }
  } catch {
    // 로깅 실패 방어
  }
}

/**
 * 애매한 경보에 대해 Jev AI에게 추가 평가 요청
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
    // Jev 미응답 시 fallback
  }
  return null;
}

/**
 * 경보를 패턴과 대조하고 Jev 평가를 거쳐 최종 판정 및 ZTNA 연동
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
    // 차단 후보만 ZTNA 거부 규칙으로 등록 (만료 시각과 근거 경보 번호 포함)
    await registerZtnaDenyRule(alert, matchedPatternName);

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
      await registerZtnaDenyRule(alert, matchedPatternName);
    } else if (confidence >= 0.5) {
      action = 'alert';
      // 알림은 xdr/alerts.log에 한 줄씩 기록
      await recordAlertLog(alert, matchedPatternName);
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
  // 정상 사용자는 거부 규칙에 등록하지 않음 (통과)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 이벤트',
  };
}
