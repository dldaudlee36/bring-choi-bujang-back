import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const BACKUP_PATH = join(root, 'backup', 'safe-policy.json');
const CONFIG_PATH = join(root, 'aleph.config.json');

/**
 * 침해 전 검증된 안전 정책 사본을 읽고 무결성을 검증합니다.
 * 사본이 없거나 손상되었으면 즉시 중단합니다.
 */
export function verifySafePolicyBackup(backupPath = BACKUP_PATH) {
  if (!existsSync(backupPath)) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 안전 정책 사본 파일(${backupPath})이 없습니다. 복구 작업을 중단합니다.`);
  }

  let raw;
  try {
    raw = readFileSync(backupPath, 'utf8');
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 정책 사본을 읽을 수 없습니다: ${err.message}`);
  }

  let backup;
  try {
    backup = JSON.parse(raw);
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 정책 사본 JSON 구문 분석에 실패했습니다: ${err.message}`);
  }

  if (backup.schema !== 'aleph.policy.backup.v1') {
    throw new Error(`S10_BACKUP_UNVERIFIED: 지원되지 않는 정책 사본 스키마입니다: ${backup.schema}`);
  }

  if (!Array.isArray(backup.policyRules) || !Array.isArray(backup.allowedRoutes)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 정책 사본에 policyRules 또는 allowedRoutes 배열이 누락되었습니다.');
  }

  // 무결성 체크섬 대조
  const canonicalData = JSON.stringify({
    version: backup.version,
    revision: backup.revision,
    policyRules: backup.policyRules,
    allowedRoutes: backup.allowedRoutes,
  });
  const expectedChecksum = createHash('sha256').update(canonicalData).digest('hex');

  if (backup.checksum !== expectedChecksum) {
    throw new Error('S10_BACKUP_UNVERIFIED: 정책 사본의 SHA-256 체크섬이 일치하지 않습니다. 사본 위변조 위험으로 중단합니다.');
  }

  return backup;
}

/**
 * 현재 시험/운영 정책을 읽어옵니다. (수정하지 않고 읽기만 수행)
 */
export async function getCurrentActivePolicy() {
  const configRaw = readFileSync(CONFIG_PATH, 'utf8');
  const config = JSON.parse(configRaw);

  const deciderUrl = pathToFileURL(join(root, 'src', 'decider.mjs'));
  const { RULE_IDS } = await import(deciderUrl.href);

  return {
    policyRules: Array.isArray(RULE_IDS) ? [...RULE_IDS] : [],
    allowedRoutes: Array.isArray(config.allowedRoutes) ? [...config.allowedRoutes] : [],
  };
}

/**
 * 안전 정책 사본과 현재 정책의 차이(Diff)만 산출합니다.
 * 실제 운영 정책은 건드리지 않습니다.
 */
export async function comparePolicies(backupPath = BACKUP_PATH) {
  const backup = verifySafePolicyBackup(backupPath);
  const current = await getCurrentActivePolicy();

  // 규칙 차이 계산
  const backupRulesSet = new Set(backup.policyRules);
  const currentRulesSet = new Set(current.policyRules);

  const missingRules = backup.policyRules.filter(r => !currentRulesSet.has(r)); // 사본에는 있으나 현재 없는 규칙 (복원 필요)
  const extraRules = current.policyRules.filter(r => !backupRulesSet.has(r));   // 현재에만 있는 비정상/변조 규칙 (제거 대상)

  // 허용 경로 차이 계산
  const backupRoutesSet = new Set(backup.allowedRoutes);
  const currentRoutesSet = new Set(current.allowedRoutes);

  const missingRoutes = backup.allowedRoutes.filter(r => !currentRoutesSet.has(r));
  const extraRoutes = current.allowedRoutes.filter(r => !backupRoutesSet.has(r));

  const hasDiff = missingRules.length > 0 || extraRules.length > 0
    || missingRoutes.length > 0 || extraRoutes.length > 0;

  return {
    targetVersion: backup.version,
    targetRevision: backup.revision,
    verifiedAt: backup.verifiedAt,
    hasDiff,
    rules: {
      backup: backup.policyRules,
      current: current.policyRules,
      missingRules,
      extraRules,
    },
    routes: {
      backup: backup.allowedRoutes,
      current: current.allowedRoutes,
      missingRoutes,
      extraRoutes,
    },
  };
}

// 직접 실행 시 차이점 및 복원 대상 버전 출력 (실제 변경은 가하지 않음)
if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  try {
    process.stdout.write('=== 🛡️ 안전 정책 사본 무결성 검증 및 변경 범위 대조 ===\n');
    const diff = await comparePolicies();

    process.stdout.write(`\n[복원 기준 버전]\n`);
    process.stdout.write(`- 대상 버전: ${diff.targetVersion} (Revision ${diff.targetRevision})\n`);
    process.stdout.write(`- 사본 검증 시점: ${diff.verifiedAt}\n`);

    process.stdout.write(`\n[변경 범위 대조 결과]\n`);
    if (!diff.hasDiff) {
      process.stdout.write('✅ 현재 정책이 검증된 안전 정책 사본과 완벽히 일치합니다. (변조 없음)\n');
    } else {
      process.stdout.write('⚠️ 정책 차이(변조 의심 범위)가 발견되었습니다:\n');
      if (diff.rules.missingRules.length > 0) {
        process.stdout.write(`  - 누락된 복원 규칙: ${diff.rules.missingRules.join(', ')}\n`);
      }
      if (diff.rules.extraRules.length > 0) {
        process.stdout.write(`  - 불필요/변조된 추가 규칙: ${diff.rules.extraRules.join(', ')}\n`);
      }
      if (diff.routes.missingRoutes.length > 0) {
        process.stdout.write(`  - 누락된 허용 경로: ${diff.routes.missingRoutes.join(', ')}\n`);
      }
      if (diff.routes.extraRoutes.length > 0) {
        process.stdout.write(`  - 불필요/변조된 추가 경로: ${diff.routes.extraRoutes.join(', ')}\n`);
      }
    }
    process.stdout.write('\nℹ️ 실제 운영 정책은 변경되지 않았습니다 (미리보기 모드).\n');
  } catch (error) {
    process.stderr.write(`\n❌ 정책 대조 중단: ${error.message}\n`);
    process.exitCode = 1;
  }
}
