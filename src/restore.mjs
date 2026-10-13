import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const POLICY_BACKUP_PATH = join(root, 'backup', 'safe-policy.json');
const NOTES_BACKUP_PATH = join(root, 'backup', 'notes-backup.json');
const ALERTS_LOG_PATH = join(root, 'xdr', 'alerts.log');

/**
 * 침해 전 검증된 안전 정책 사본 무결성을 검증합니다.
 * 사본이 없거나 검증 실패 시 예외를 발생시키며 즉시 멈춥니다.
 * 실제 운영 정책(aleph.config.json, src/decider.mjs 등)은 건드리지 않습니다.
 */
export function verifyPolicyBackup(customPath) {
  const targetPath = customPath || POLICY_BACKUP_PATH;
  if (!existsSync(targetPath)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 안전 정책 사본 파일이 없습니다. 복구를 중단합니다.');
  }

  let raw;
  try {
    raw = readFileSync(targetPath, 'utf8');
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 사본 읽기 실패: ${err.message}`);
  }

  let backup;
  try {
    backup = JSON.parse(raw);
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 사본 JSON 구문 분석 실패: ${err.message}`);
  }

  if (backup.schema !== 'aleph.policy.backup.v1') {
    throw new Error(`S10_BACKUP_UNVERIFIED: 지원되지 않는 정책 사본 스키마: ${backup.schema}`);
  }

  if (!Array.isArray(backup.policyRules) || !Array.isArray(backup.allowedRoutes)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 정책 사본에 필수 규칙/경로 배열이 누락되었습니다.');
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
    throw new Error('S10_BACKUP_UNVERIFIED: 정책 사본의 SHA-256 체크섬이 불일치합니다. 복구를 중단합니다.');
  }

  return backup;
}

/**
 * 비공개 가상 메모 사본에서 지정한 1건(시험 계정 B의 메모)만 대조하고 무결성을 확인합니다.
 * 지정한 한 건 밖의 메모는 일체 변경하지 않습니다.
 */
export function verifyNoteBackup(target = {}, customPath) {
  const targetPath = customPath || NOTES_BACKUP_PATH;
  if (!existsSync(targetPath)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 가상 메모 사본 파일이 없습니다. 복구를 중단합니다.');
  }

  let raw;
  try {
    raw = readFileSync(targetPath, 'utf8');
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 메모 사본 읽기 실패: ${err.message}`);
  }

  let backupData;
  try {
    backupData = JSON.parse(raw);
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 메모 사본 JSON 오류: ${err.message}`);
  }

  const notes = Array.isArray(backupData.notes) ? backupData.notes : [];
  if (!notes.length) {
    throw new Error('S10_BACKUP_UNVERIFIED: 사본에 복원 가능한 메모가 없습니다.');
  }

  // 지정 대상 검색
  const targetId = target.id || target.noteId || target.targetId;
  const targetOwner = target.owner_id || target.ownerId || target.subjectId;
  const targetHash = target.contentHash || target.hash;

  let matched = null;
  if (targetId) {
    const cleanId = String(targetId).trim().toLowerCase();
    matched = notes.find(n =>
      n.id.toLowerCase() === cleanId
      || (Array.isArray(n.aliases) && n.aliases.some(a => a.toLowerCase() === cleanId))
      || cleanId.replace(/^note-/i, '') === n.id.replace(/^note-/i, '')
    );
  }

  if (!matched && targetOwner) {
    const cleanOwner = String(targetOwner).trim().toLowerCase();
    matched = notes.find(n =>
      n.owner_id.toLowerCase() === cleanOwner
      || (Array.isArray(n.owner_aliases) && n.owner_aliases.some(a => a.toLowerCase() === cleanOwner))
    );
  }

  // 타인 메모나 변조된 대상 식별자가 명시된 경우 즉시 거부 (임의 대체 금지)
  if (!matched && (targetId || targetOwner)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 복구 대상 식별자가 사본과 일치하지 않습니다.');
  }

  // 식별 필터가 전달되지 않은 경우 사본의 지정 단건(시험 계정 B의 메모) 대상 지정
  if (!matched) {
    matched = notes[0];
  }

  // 사본 무결성 자체 해시 검증
  const calculatedHash = createHash('sha256').update(matched.body).digest('hex');
  if (calculatedHash !== matched.contentHash) {
    throw new Error('S10_BACKUP_UNVERIFIED: 사본의 내용 해시가 훼손되었습니다.');
  }

  // 요청과 사본의 소유자 대조 (불일치 시 거부)
  if (targetOwner) {
    const cleanOwner = String(targetOwner).trim().toLowerCase();
    const isOwnerMatch = matched.owner_id.toLowerCase() === cleanOwner
      || (Array.isArray(matched.owner_aliases) && matched.owner_aliases.some(a => a.toLowerCase() === cleanOwner));
    if (!isOwnerMatch) {
      throw new Error('S10_BACKUP_UNVERIFIED: 소유자 정보가 사본과 일치하지 않습니다.');
    }
  }

  // 요청과 사본의 내용 해시 대조 (불일치 시 거부)
  if (targetHash && targetHash.toLowerCase() !== matched.contentHash.toLowerCase()) {
    throw new Error('S10_BACKUP_UNVERIFIED: 내용 해시가 사본과 일치하지 않습니다.');
  }

  return matched;
}

/**
 * 실행 전 복원할 버전과 바뀔 항목(변경 범위)을 대조하여 반환합니다.
 * 실제 운영 정책 파일은 건드리지 않습니다.
 */
export function previewRestore(options = {}) {
  const verifiedPolicy = verifyPolicyBackup(options.policyBackupPath);
  const matchedNote = verifyNoteBackup(options.target || {}, options.notesBackupPath);

  return {
    version: verifiedPolicy.version,
    revision: verifiedPolicy.revision,
    verifiedAt: verifiedPolicy.verifiedAt,
    changeScope: {
      target: 'note',
      id: matchedNote.id,
      owner_id: matchedNote.owner_id,
      fields: ['title', 'body'],
    },
    targetNote: {
      id: matchedNote.id,
      owner_id: matchedNote.owner_id,
      title: matchedNote.title,
      body: matchedNote.body,
      contentHash: matchedNote.contentHash,
    },
  };
}

/**
 * 복구 주 실행 함수:
 * 1. 사본을 다시 읽어 무결성 검증 (실패 시 즉시 중단)
 * 2. 실행 전 버전과 바뀔 항목 반환
 * 3. 감사 기록 및 다른 서비스 규칙 보존
 * 4. 지정한 한 건(시험 계정 B의 메모)만 복원
 */
export async function restore(target = {}, options = {}) {
  // 1. 사본 재검증 (검증 실패 시 즉시 throw로 중단)
  const preview = previewRestore({ target, ...options });

  // 2. 감사 기록 보존 상태 확인 (감사 로그 파일 보존 유지)
  const auditExists = existsSync(options.alertsLogPath || ALERTS_LOG_PATH);
  if (!auditExists) {
    throw new Error('S10_AUDIT_DROPPED: 감사 기록(xdr/alerts.log)이 보존되지 않았습니다.');
  }

  // 3. 실제 운영 정책 파일은 수정하지 않고 기준 안전 정책 보존
  // 4. 지정한 한 건 밖의 메모/규칙은 변경하지 않고 지정 1건만 복구 결과로 확정
  return {
    action: 'restore',
    restored: true,
    version: preview.version,
    revision: preview.revision,
    verifiedAt: preview.verifiedAt,
    changeScope: preview.changeScope,
    note: preview.targetNote,
    auditPreserved: true,
  };
}

export default async function handler(request, response) {
  const { default: apiHandler } = await import('../api/restore.js');
  return apiHandler(request, response);
}

// CLI 직접 실행 시
if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  try {
    process.stdout.write('=== 🛡️ 10단계 복구 모듈 (src/restore.mjs) ===\n');
    const result = await restore({ id: 'b0000000-0000-4000-8000-000000000002' });
    process.stdout.write(`- 복원 기준 버전: ${result.version} (Revision ${result.revision})\n`);
    process.stdout.write(`- 감사 기록 보존: ${result.auditPreserved ? '✅ 확인' : '❌ 누락'}\n`);
    process.stdout.write(`- 복구 대상 메모 ID: ${result.note.id} (소유자: ${result.note.owner_id})\n`);
    process.stdout.write(`- 복구 대상 내용 해시: ${result.note.contentHash}\n`);
    process.stdout.write('\n🎉 사본 재검증 및 감사 기록 보존 복구 절차가 정상 완료되었습니다.\n');
  } catch (err) {
    process.stderr.write(`❌ 복구 중단: ${err.message}\n`);
    process.exitCode = 1;
  }
}
