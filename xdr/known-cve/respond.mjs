import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '..', '..');
const DENY_RULES_PATH = join(ROOT_DIR, 'xdr', 'deny-rules.json');
const ALERTS_LOG_PATH = join(ROOT_DIR, 'xdr', 'alerts.log');
const FIXTURE_PATH = join(ROOT_DIR, 'xdr', 'fixtures', 'known-cve.json');

// 기본 규칙 만료 시각 (작전 종료일 2026-10-16 이후의 유효 시각)
const DEFAULT_EXPIRES_AT = '2026-10-18T00:00:00.000Z';

/**
 * 판정기 거부 규칙 파일(xdr/deny-rules.json) 읽기
 */
export async function loadDenyRules(filePath = DENY_RULES_PATH) {
  try {
    const raw = await readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * 판정기 거부 규칙 파일(xdr/deny-rules.json) 저장
 */
export async function saveDenyRules(rules, filePath = DENY_RULES_PATH) {
  const content = `${JSON.stringify(rules, null, 2)}\n`;
  await writeFile(filePath, content, 'utf8');
}

/**
 * xdr/alerts.log 에 알림 한 줄 추가
 */
export async function appendAlertLog(alert, decision, logPath = ALERTS_LOG_PATH) {
  const timestamp = alert?.timestamp || new Date().toISOString();
  const alertId = alert?.id || 'unknown';
  const ip = alert?.data?.srcip || '-';
  const user = alert?.data?.srcuser || '-';
  const reason = decision?.reason || '애매한 시도';

  const line = `${timestamp} [ALERT] id=${alertId} ip=${ip} user=${user} reason="${reason}"\n`;
  await appendFile(logPath, line, 'utf8');
}

/**
 * 단일 경보를 판단하고 차단 후보는 거부 규칙에 등록, 애매한 건은 alerts.log에 기록
 * - 정상 사용자(record)는 거부 규칙에 절대 등록하지 않음
 *
 * @param {object} alert Wazuh 형태 경보
 * @param {object} options 설정 옵션
 * @returns {Promise<{ action: string, confidence: number, reason: string, ruleAdded: boolean }>}
 */
export async function respond(alert, options = {}) {
  const denyRulesPath = options.denyRulesPath || DENY_RULES_PATH;
  const alertsLogPath = options.alertsLogPath || ALERTS_LOG_PATH;
  const expiresAt = options.expiresAt || DEFAULT_EXPIRES_AT;

  const decision = await decide(alert);

  // 1. 명확한 공격 (block) -> 거부 규칙 생성 및 추가
  if (decision.action === 'block') {
    const ip = alert?.data?.srcip;
    const alertId = alert?.id || 'unknown';

    if (ip) {
      const currentRules = await loadDenyRules(denyRulesPath);
      const existingIdx = currentRules.findIndex(r => r.alertId === alertId);

      const newRule = {
        ruleId: `xdr_deny_${alertId}`,
        alertId,
        ip,
        user: alert?.data?.srcuser || null,
        expiresAt,
        reason: decision.reason,
        action: 'deny',
      };

      if (existingIdx >= 0) {
        currentRules[existingIdx] = newRule;
      } else {
        currentRules.push(newRule);
      }

      await saveDenyRules(currentRules, denyRulesPath);
      return { ...decision, ruleAdded: true };
    }
  }

  // 2. 애매한 시도 (alert) -> alerts.log 에 한 줄 누적
  if (decision.action === 'alert') {
    await appendAlertLog(alert, decision, alertsLogPath);
    return { ...decision, ruleAdded: false };
  }

  // 3. 정상 이벤트 (record) -> 거부 규칙 등록 없이 안전 통과
  return { ...decision, ruleAdded: false };
}

/**
 * known-cve.json 전체 시험 경보를 순회하며 차단 규칙 및 알림 로그 반영
 */
export async function processAllAlerts(fixturePath = FIXTURE_PATH, options = {}) {
  const raw = await readFile(fixturePath, 'utf8');
  const fixture = JSON.parse(raw);

  if (!Array.isArray(fixture?.alerts)) {
    throw new Error('경보 목록이 올바르지 않습니다.');
  }

  const results = { block: 0, alert: 0, record: 0, rulesAdded: 0 };

  for (const alert of fixture.alerts) {
    const res = await respond(alert, options);
    if (res.action === 'block') {
      results.block += 1;
      if (res.ruleAdded) results.rulesAdded += 1;
    } else if (res.action === 'alert') {
      results.alert += 1;
    } else {
      results.record += 1;
    }
  }

  return results;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const summary = await processAllAlerts();
    process.stdout.write(`연동 완료: 차단 ${summary.block}건 (거부 규칙 갱신), 알림 ${summary.alert}건 (alerts.log 기록), 통과 ${summary.record}건\n`);
  } catch (error) {
    process.stderr.write(`연동 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
