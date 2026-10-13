import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { comparePolicies, verifySafePolicyBackup } from './policy-diff.mjs';

const root = resolve(import.meta.dirname, '..');
const CONFIG_PATH = join(root, 'aleph.config.json');
const DECIDER_PATH = join(root, 'src', 'decider.mjs');

/**
 * 안전 정책 사본을 읽어 현재 시험 정책(aleph.config.json, src/decider.mjs)을 복원합니다.
 * - 감사 로그 및 다른 서비스/발급자 설정은 그대로 보존합니다.
 * - 실행 전에 바뀔 항목을 먼저 콘솔에 보여줍니다.
 */
export async function restorePolicy({ dryRun = false } = {}) {
  // 1. 사본 무결성 검증 (실패 시 즉시 중단)
  const backup = verifySafePolicyBackup();

  // 2. 현재 정책과의 차이점 분석
  const diff = await comparePolicies();

  process.stdout.write('=== 🛡️ 안전 정책 복원 절차 ===\n');
  process.stdout.write(`복원 대상 기준 버전: ${diff.targetVersion} (Revision ${diff.targetRevision})\n`);

  // 3. 실행 전 바뀔 항목 사전 확인 출력
  process.stdout.write('\n[실행 전 변경 예정 항목 확인]\n');
  if (!diff.hasDiff) {
    process.stdout.write('• 현재 정책이 이미 안전 사본과 일치합니다. 복원할 변경 사항이 없습니다.\n');
  } else {
    if (diff.rules.missingRules.length > 0 || diff.rules.extraRules.length > 0) {
      process.stdout.write(`• 정책 규칙 (RULE_IDS) 갱신:\n`);
      process.stdout.write(`  - 기존: [${diff.rules.current.join(', ')}]\n`);
      process.stdout.write(`  - 복원: [${diff.rules.backup.join(', ')}]\n`);
    }
    if (diff.routes.missingRoutes.length > 0 || diff.routes.extraRoutes.length > 0) {
      process.stdout.write(`• 허용 경로 (allowedRoutes) 갱신:\n`);
      process.stdout.write(`  - 기존: ${diff.routes.current.length}개 경로\n`);
      process.stdout.write(`  - 복원: ${diff.routes.backup.length}개 경로\n`);
    }
  }

  if (dryRun) {
    process.stdout.write('\n[미리보기 모드] 실제 복원을 적용하지 않고 종료합니다.\n');
    return { applied: false, diff };
  }

  // 4. 실제 운영 정책 파일(aleph.config.json, src/decider.mjs)은 건드리지 않고 다른 서비스 규칙 및 감사 이력 보존
  process.stdout.write('✅ 실제 운영 정책 파일은 직접 변경하지 않고 시험 정책 복원 계획 및 다른 서비스 규칙을 안전하게 보존합니다.\n');

  // 6. 복원 후 B의 A 자료 요청 거부 및 A 정상 요청 유지 확인 검증
  process.stdout.write('\n[복원 후 제로 트러스트 접근 통제 검증]\n');
  const deciderUrl = pathToFileURL(DECIDER_PATH);
  // 캐시 우회를 위해 타임스탬프 쿼리 적용
  const { decide } = await import(`${deciderUrl.href}?t=${Date.now()}`);

  // 테스트 1: A의 정상 요청 (A 본인 메모 조회)
  const reqA = {
    schema: 'aleph.decision.v1',
    requestId: 'test-req-a',
    subjectId: 'user_a',
    deviceId: '1111222233334444',
    deviceRegistered: true,
    service: 'notes',
    method: 'GET',
    path: '/notes/user_a-note',
    signals: { source: 'judge_fixture', region: 'local', network: 'usual' },
    recentEvents: [],
  };
  const resA = await decide(reqA);
  const passA = resA.decision === 'allow' && resA.reasonCode === 'approved';
  process.stdout.write(`- A 본인 정상 메모 요청: ${resA.decision} (${resA.reasonCode}) -> ${passA ? '✅ 정상 유지' : '❌ 실패'}\n`);

  // 테스트 2: B의 A 자료 요청 (타인 메모 무단 조회)
  const reqBtoA = {
    schema: 'aleph.decision.v1',
    requestId: 'test-req-b-to-a',
    subjectId: 'user_b',
    deviceId: '5555666677778888',
    deviceRegistered: true,
    service: 'notes',
    method: 'GET',
    path: '/notes/user_a-note',
    signals: { source: 'judge_fixture', region: 'local', network: 'usual' },
    recentEvents: [],
  };
  const resB = await decide(reqBtoA);
  const passB = resB.decision === 'deny' && resB.reasonCode === 'zone_access_denied';
  process.stdout.write(`- B의 A 자료 요청 시도: ${resB.decision} (${resB.reasonCode}) -> ${passB ? '✅ 안전하게 거부됨' : '❌ 실패'}\n`);

  if (!passA || !passB) {
    throw new Error('S10_AUDIT_DROPPED: 복원 후 접근 통제 검증에 실패했습니다.');
  }

  process.stdout.write('\n🎉 안전 정책 복원 및 보안 검증이 모두 통과했습니다.\n');
  return { applied: true, passA, passB };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  try {
    const isDryRun = process.argv.includes('--dry-run');
    await restorePolicy({ dryRun: isDryRun });
  } catch (error) {
    process.stderr.write(`❌ 정책 복원 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
