import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import handler from '../api/restore.js';

const root = resolve(import.meta.dirname, '..');
const backupPath = join(root, 'backup', 'notes-backup.json');
const backupData = JSON.parse(readFileSync(backupPath, 'utf8'));
const expectedNote = backupData.notes[0]; // 시험 계정 B의 메모 사본

function mockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(data) { this.body = data; return this; }
  };
  return res;
}

process.stdout.write('=== 🛡️ 10단계 시험 계정 B 메모 복구 경로 및 무결성 검증 ===\n');

// 1. 시험 계정 B 메모 정상 복구 검증
const res = mockRes();
await handler({
  method: 'POST',
  headers: {},
  body: { id: expectedNote.id },
}, res);

if (res.statusCode !== 200 || !res.body?.note) {
  process.stderr.write(`❌ 복구 실패 (HTTP ${res.statusCode}): ${JSON.stringify(res.body)}\n`);
  process.exitCode = 1;
} else {
  const restored = res.body.note;
  const idMatch = restored.id === expectedNote.id;
  const ownerMatch = restored.owner_id === expectedNote.owner_id;
  const hashMatch = restored.contentHash === expectedNote.contentHash;

  process.stdout.write(`- 복구 대상 메모 ID: ${restored.id} (${idMatch ? '✅ 사본과 일치' : '❌ 불일치'})\n`);
  process.stdout.write(`- 복구 대상 소유자: ${restored.owner_id} (${ownerMatch ? '✅ 사본과 일치' : '❌ 불일치'})\n`);
  process.stdout.write(`- 복구 대상 내용 해시: ${restored.contentHash} (${hashMatch ? '✅ 사본과 일치' : '❌ 불일치'})\n`);
  process.stdout.write(`- 복원 기준 버전: ${res.body.version} (Revision ${res.body.revision})\n`);
  process.stdout.write(`- 감사 기록 보존 확인: ${res.body.auditPreserved ? '✅ 보존됨' : '❌ 누락'}\n`);

  if (!idMatch || !ownerMatch || !hashMatch || !res.body.auditPreserved) {
    process.stderr.write('❌ 복구 대상 정보 또는 감사 기록 보존이 일치하지 않습니다.\n');
    process.exitCode = 1;
  } else {
    process.stdout.write('\n🎉 복구 대상 한 건의 ID·소유자·내용 해시가 사본과 완벽히 일치하며 감사 기록이 보존되었습니다.\n');
  }
}

// 2. 검증 실패 시 중단 테스트 (해시 위변조 시 복원 거부)
const failRes = mockRes();
await handler({
  method: 'POST',
  headers: {},
  body: { id: expectedNote.id, contentHash: 'tampered_invalid_hash' },
}, failRes);

if (failRes.statusCode === 400 && failRes.body?.aborted) {
  process.stdout.write('✅ 해시 변조 검증 실패 시 정상적으로 복원을 중단합니다. (S10_BACKUP_UNVERIFIED 방어 완료)\n');
} else {
  process.stderr.write(`❌ 해시 검증 실패 시 중단 처리 오류: HTTP ${failRes.statusCode}\n`);
  process.exitCode = 1;
}

// 3. 존재하지 않거나 허위 ID 요청 시 복원 거부 테스트
const fakeIdRes = mockRes();
await handler({
  method: 'POST',
  headers: {},
  body: { id: 'attacker-tampered-id' },
}, fakeIdRes);

if (fakeIdRes.statusCode === 400 && fakeIdRes.body?.aborted) {
  process.stdout.write('✅ 허위 대상 ID 요청 시 복원을 거부하고 즉시 중단합니다.\n');
} else {
  process.stderr.write(`❌ 허위 ID 차단 실패: HTTP ${fakeIdRes.statusCode}\n`);
  process.exitCode = 1;
}

// 4. 타인/변조 소유자 요청 시 복원 거부 테스트
const badOwnerRes = mockRes();
await handler({
  method: 'POST',
  headers: {},
  body: { id: expectedNote.id, owner_id: 'bad-owner' },
}, badOwnerRes);

if (badOwnerRes.statusCode === 400 && badOwnerRes.body?.aborted) {
  process.stdout.write('✅ 변조 소유자 요청 시 복원을 거부하고 즉시 중단합니다.\n');
} else {
  process.stderr.write(`❌ 변조 소유자 차단 실패: HTTP ${badOwnerRes.statusCode}\n`);
  process.exitCode = 1;
}

// 5. 식별자 미지정 기본 복구 요청 시 지정 단건 메모(계정 B) 안전 복구 확인 테스트
const emptyRes = mockRes();
await handler({
  method: 'POST',
  headers: {},
  body: {},
}, emptyRes);

if (emptyRes.statusCode === 200 && emptyRes.body?.note?.id === expectedNote.id) {
  process.stdout.write('✅ 파라미터 미지정 요청 시 사본 내 지정 1건(계정 B 메모) 안전 복구를 확인했습니다.\n');
} else {
  process.stderr.write(`❌ 기본 단건 복구 오류: HTTP ${emptyRes.statusCode}\n`);
  process.exitCode = 1;
}

// 6. 사전 검증 / 미리보기(preview / dryRun) 요청 시 버전과 바뀔 항목 확인 테스트
const previewRes = mockRes();
await handler({
  method: 'POST',
  headers: {},
  body: { dryRun: true },
}, previewRes);

if (previewRes.statusCode === 200 && previewRes.body?.preview && previewRes.body?.version && previewRes.body?.changeScope) {
  process.stdout.write('✅ 사전 검증(dryRun) 시 복원 전 버전과 바뀔 항목 미리보기를 확인했습니다.\n');
} else {
  process.stderr.write(`❌ 사전 검증 미리보기 오류: HTTP ${previewRes.statusCode}\n`);
  process.exitCode = 1;
}
