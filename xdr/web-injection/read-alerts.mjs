import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// 토큰, 개인키, 암호 등 비밀값 형태 정규식
const SECRET_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_secret_[A-Za-z0-9_-]{12,}|\bsk-[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;

/**
 * 개별 Wazuh 웹 주입 경보 객체에서 시각, 출발 주소, 계정, 규칙 수준, 설명만 추출
 */
export function extractAlertFields(alert) {
  if (!alert || typeof alert !== 'object') return null;

  const timestamp = typeof alert.timestamp === 'string' ? alert.timestamp : '';
  const srcip = typeof alert.data?.srcip === 'string' ? alert.data.srcip : '';
  const srcuser = typeof alert.data?.srcuser === 'string' ? alert.data.srcuser : (alert.data?.srcuser ?? '-');
  const level = typeof alert.rule?.level === 'number' ? alert.rule.level : 0;
  const description = typeof alert.rule?.description === 'string' ? alert.rule.description : '';

  const sanitize = (value) => (typeof value === 'string' && SECRET_PATTERN.test(value) ? '[FILTERED]' : value);

  return {
    timestamp: sanitize(timestamp),
    srcip: sanitize(srcip),
    srcuser: sanitize(srcuser),
    level,
    description: sanitize(description),
  };
}

/**
 * web-injection.json 경보 파일을 읽어 5개 핵심 속성 배열로 반환
 */
export async function readAlerts(filePath) {
  const defaultPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'web-injection.json');
  const targetPath = filePath ? resolve(filePath) : defaultPath;
  const raw = await readFile(targetPath, 'utf8');
  const fixture = JSON.parse(raw);

  if (!Array.isArray(fixture?.alerts)) {
    throw new Error('경보 목록(alerts)이 올바르지 않습니다.');
  }

  return fixture.alerts.map(extractAlertFields).filter(Boolean);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const alerts = await readAlerts(process.argv[2]);
    for (const item of alerts) {
      process.stdout.write(`${item.timestamp} | ${item.srcip} | ${item.srcuser} | 레벨 ${item.level} | ${item.description}\n`);
    }
  } catch (error) {
    process.stderr.write(`경보 읽기 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
