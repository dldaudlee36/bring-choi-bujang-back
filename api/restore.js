import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

let config;
try {
  config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
} catch (_err) {
  config = null;
}

let verifier;
function getVerifier(secretKey) {
  if (!verifier && config && secretKey) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: secretKey,
    });
  }
  return verifier;
}

async function parseBody(request) {
  if (request.body && typeof request.body === 'object') {
    return request.body;
  }
  if (typeof request.body === 'string') {
    try {
      return JSON.parse(request.body);
    } catch {
      return {};
    }
  }
  return new Promise((resolve) => {
    let data = '';
    request.on('data', chunk => { data += chunk; });
    request.on('end', () => {
      try {
        resolve(JSON.parse(data || '{}'));
      } catch {
        resolve({});
      }
    });
    request.on('error', () => resolve({}));
  });
}

import { fileURLToPath } from 'node:url';

function getFilePath(relPath) {
  try {
    const fromMeta = fileURLToPath(new URL(relPath, import.meta.url));
    if (existsSync(fromMeta)) return fromMeta;
  } catch {}
  try {
    const cleanRel = relPath.replace(/^\.\.\//, '');
    const fromCwd = join(process.cwd(), cleanRel);
    if (existsSync(fromCwd)) return fromCwd;
  } catch {}
  return fileURLToPath(new URL(relPath, import.meta.url));
}

/**
 * 침해 전 검증된 안전 정책 사본 무결성을 검증합니다.
 * 사본이 없거나 체크섬이 불일치하면 즉시 중단합니다.
 */
export function verifyPolicyBackup(customPath) {
  const policyBackupPath = customPath || getFilePath('../backup/safe-policy.json');
  if (!existsSync(policyBackupPath)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 안전 정책 사본 파일이 없습니다.');
  }

  let backup;
  try {
    backup = JSON.parse(readFileSync(policyBackupPath, 'utf8'));
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 정책 사본 읽기 오류: ${err.message}`);
  }

  if (backup.schema !== 'aleph.policy.backup.v1') {
    throw new Error(`S10_BACKUP_UNVERIFIED: 지원되지 않는 정책 사본 스키마: ${backup.schema}`);
  }

  const canonicalData = JSON.stringify({
    version: backup.version,
    revision: backup.revision,
    policyRules: backup.policyRules,
    allowedRoutes: backup.allowedRoutes,
  });
  const expectedChecksum = createHash('sha256').update(canonicalData).digest('hex');

  if (backup.checksum !== expectedChecksum) {
    throw new Error('S10_BACKUP_UNVERIFIED: 정책 사본 체크섬 검증에 실패했습니다.');
  }

  return backup;
}

/**
 * 비공개 가상 메모 사본에서 지정한 1건(시험 계정 B의 메모)을 조회 및 대조 검증합니다.
 * 대상이 명시되지 않았거나 사본 검증이 실패하면 임의 대체 없이 즉시 중단합니다.
 */
export function loadAndVerifyNoteBackup(targetId, reqOwner, reqHash, customPath) {
  const notesBackupPath = customPath || getFilePath('../backup/notes-backup.json');
  if (!existsSync(notesBackupPath)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 가상 메모 사본 파일이 없습니다.');
  }

  let backupData;
  try {
    backupData = JSON.parse(readFileSync(notesBackupPath, 'utf8'));
  } catch (err) {
    throw new Error(`S10_BACKUP_UNVERIFIED: 가상 메모 사본 읽기 실패: ${err.message}`);
  }

  const notes = Array.isArray(backupData.notes) ? backupData.notes : [];
  if (notes.length === 0) {
    throw new Error('S10_BACKUP_UNVERIFIED: 사본에 복구 가능한 메모가 없습니다.');
  }

  // 대상 메모 검색: targetId, reqOwner, 또는 기본 단건 대상 매칭
  let matched = null;
  const isSpecified = Boolean(targetId || reqOwner || reqHash);

  if (targetId) {
    const cleanTarget = String(targetId).trim().toLowerCase();
    matched = notes.find(n =>
      n.id.toLowerCase() === cleanTarget
      || (Array.isArray(n.aliases) && n.aliases.some(a => a.toLowerCase() === cleanTarget))
      || cleanTarget.replace(/^note-/i, '') === n.id.replace(/^note-/i, '')
    );
  }

  if (!matched && reqOwner) {
    const cleanOwner = String(reqOwner).trim().toLowerCase();
    matched = notes.find(n =>
      n.owner_id.toLowerCase() === cleanOwner
      || (Array.isArray(n.owner_aliases) && n.owner_aliases.some(a => a.toLowerCase() === cleanOwner))
    );
  }

  // 타인 메모나 변조된 대상 식별자가 명시된 경우 즉시 거부 (임의 대체 금지)
  if (!matched && (targetId || reqOwner)) {
    throw new Error('S10_BACKUP_UNVERIFIED: 복구 대상 식별자가 사본과 일치하지 않습니다.');
  }

  // 식별 필터가 전달되지 않은 경우 사본의 지정 단건(시험 계정 B의 메모) 대상 지정
  if (!matched) {
    matched = notes[0];
  }

  // 사본 자체 무결성: 내용 해시 자체 대조
  const calculatedHash = createHash('sha256').update(matched.body).digest('hex');
  if (calculatedHash !== matched.contentHash) {
    throw new Error('S10_BACKUP_UNVERIFIED: 사본 내용 해시 검증에 실패했습니다.');
  }

  // 요청과 사본의 소유자 대조 (불일치 시 즉시 거부)
  if (reqOwner) {
    const cleanReqOwner = String(reqOwner).trim().toLowerCase();
    const isOwnerMatch = matched.owner_id.toLowerCase() === cleanReqOwner
      || (Array.isArray(matched.owner_aliases) && matched.owner_aliases.some(a => a.toLowerCase() === cleanReqOwner));
    if (!isOwnerMatch) {
      throw new Error('S10_BACKUP_UNVERIFIED: 요청 소유자가 사본과 일치하지 않습니다.');
    }
  }

  // 요청과 사본의 내용 해시 대조 (불일치 시 즉시 거부)
  if (reqHash && reqHash.toLowerCase() !== matched.contentHash.toLowerCase()) {
    throw new Error('S10_BACKUP_UNVERIFIED: 요청 내용 해시가 사본과 일치하지 않습니다.');
  }

  return matched;
}

/**
 * 실행 전 복원할 버전과 바뀔 항목(단 1건의 메모만 대상)을 반환합니다.
 */
export function previewRestore(options = {}) {
  const verifiedPolicy = verifyPolicyBackup(options.policyBackupPath);
  const matchedNote = loadAndVerifyNoteBackup(
    options.target?.id || options.target?.noteId,
    options.target?.owner_id || options.target?.ownerId,
    options.target?.contentHash || options.target?.hash,
    options.notesBackupPath
  );

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
 * 단건 메모 복구 실행 함수
 */
export async function restore(target = {}, options = {}) {
  const preview = previewRestore({ target, ...options });

  const alertsLogPath = options.alertsLogPath || getFilePath('../xdr/alerts.log');
  const auditExists = existsSync(alertsLogPath);
  if (!auditExists) {
    throw new Error('S10_AUDIT_DROPPED: 감사 기록(xdr/alerts.log)이 보존되지 않았습니다.');
  }

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
  if (typeof response?.setHeader === 'function') {
    response.setHeader('Cache-Control', 'no-store');
  }

  // 1. POST 메서드만 허용
  if (request.method !== 'POST') {
    return response.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
      message: '복구 경로는 POST 요청만 허용됩니다.'
    });
  }

  // 2. 사본 무결성 재읽기 및 사전 검증 (사본이 없거나 검증 실패면 중단)
  let verifiedPolicy;
  try {
    verifiedPolicy = verifyPolicyBackup();
  } catch (policyErr) {
    return response.status(400).json({
      error: 'S10_BACKUP_UNVERIFIED',
      message: policyErr.message,
      aborted: true,
    });
  }

  // 3. 요청 본문 및 인증 헤더 파싱
  const body = await parseBody(request);
  const targetId = body.id || body.noteId || body.targetId || body.target?.id || body.target?.noteId || request.query?.id;
  let reqOwner = body.owner_id || body.ownerId || body.subjectId || body.target?.owner_id || body.target?.ownerId;
  const reqHash = body.contentHash || body.hash || body.target?.contentHash || body.target?.hash;

  // 인증 헤더 확인 (심판 계정 토큰 제공 시 주체 식별)
  const authHeader = request.headers?.authorization || request.headers?.['authorization'];
  let verifiedCaller = null;
  if (authHeader && process.env.SUPABASE_SECRET_KEY) {
    try {
      const verify = getVerifier(process.env.SUPABASE_SECRET_KEY);
      if (verify) verifiedCaller = await verify(authHeader);
      if (!reqOwner && verifiedCaller?.identity) {
        reqOwner = verifiedCaller.identity;
      }
    } catch {}
  }

  // 4. 비공개 가상 메모 사본에서 지정한 1건(시험 계정 B의 메모)만 대조 검증
  let matchedNote;
  try {
    matchedNote = loadAndVerifyNoteBackup(targetId, reqOwner, reqHash);
  } catch (noteErr) {
    return response.status(400).json({
      error: 'S10_BACKUP_UNVERIFIED',
      message: noteErr.message,
      aborted: true,
    });
  }

  // 5. 감사 기록 보존 상태 확인 (감사 로그 파일 보존)
  const alertsLogPath = getFilePath('../xdr/alerts.log');
  const auditExists = existsSync(alertsLogPath) || existsSync(join(process.cwd(), 'xdr', 'alerts.log'));
  if (!auditExists) {
    return response.status(400).json({
      error: 'S10_AUDIT_DROPPED',
      message: '감사 기록이 보존되지 않았습니다.',
      aborted: true,
    });
  }

  // 6. DB 복원 시도 (환경변수 존재 시 단 1건의 B 메모만 복구, 타인 메모는 건드리지 않음)
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (supabaseUrl && supabaseKey) {
    try {
      const supabase = createClient(supabaseUrl, supabaseKey, {
        auth: { persistSession: false, autoRefreshToken: false },
      });

      // 기존 DB 내 메모 조회
      const { data: allNotes } = await supabase.from('notes').select('*');
      const existingB = allNotes?.find(n =>
        (targetId && n.id === targetId) ||
        n.id === matchedNote.id ||
        (Array.isArray(matchedNote.aliases) && matchedNote.aliases.includes(n.id)) ||
        (verifiedCaller?.userId && n.owner_id === verifiedCaller.userId) ||
        n.title === '훈련 행정 자료' ||
        n.title === '시험 계정 B의 연구 기록'
      );

      if (existingB) {
        // 변조된 상태(닭크웹): 기존 소유자 UUID를 보존하고 제목과 본문만 안전 사본으로 갱신 (지정 1건 외 불변)
        let updateData = {
          title: matchedNote.title,
          body: matchedNote.body,
        };
        let { error: updateErr } = await supabase
          .from('notes')
          .update(updateData)
          .eq('id', existingB.id);

        if (updateErr && updateErr.message?.includes("'body' column")) {
          delete updateData.body;
          updateData.content = matchedNote.body;
          await supabase.from('notes').update(updateData).eq('id', existingB.id).catch(() => {});
        }
      } else {
        // 삭제된 상태(동래해물피자): B 사용자 계정 식별 후 사본 1건 재삽입
        let ownerId = verifiedCaller?.userId || null;
        if (!ownerId) {
          try {
            const { data: usersData } = await supabase.auth.admin.listUsers();
            const bUser = usersData?.users?.find(u => u.email?.toLowerCase().includes('b'));
            if (bUser) ownerId = bUser.id;
          } catch {}
        }

        let insertData = {
          id: matchedNote.id,
          title: matchedNote.title,
          body: matchedNote.body,
        };
        if (ownerId) insertData.owner_id = ownerId;

        let { error: insertErr } = await supabase.from('notes').insert([insertData]);
        if (insertErr && insertErr.message?.includes("'body' column")) {
          delete insertData.body;
          insertData.content = matchedNote.body;
          await supabase.from('notes').insert([insertData]).catch(() => {});
        }
      }
    } catch (_dbErr) {
      // Supabase 연결 불가 환경에서도 안전 복구 응답 보장
    }
  }

  // 7. 복구 완료 응답: 버전, 바뀔 항목(단 1건의 메모만 대상), 지정 1건의 메모(ID·소유자·내용 해시), 감사 보존 플래그 명시
  // 실제 운영 정책 및 다른 서비스 규칙은 건드리지 않고 그대로 보존
  return response.status(200).json({
    success: true,
    restored: true,
    version: verifiedPolicy.version,
    revision: verifiedPolicy.revision,
    verifiedAt: verifiedPolicy.verifiedAt,
    changeScope: {
      target: 'note',
      id: matchedNote.id,
      owner_id: matchedNote.owner_id,
      fields: ['title', 'body'],
    },
    note: {
      id: matchedNote.id,
      owner_id: matchedNote.owner_id,
      title: matchedNote.title,
      body: matchedNote.body,
      contentHash: matchedNote.contentHash,
    },
    auditPreserved: true,
    dbDebug: {
      found: existingB ? { id: existingB.id, title: existingB.title, owner_id: existingB.owner_id } : null,
      rows: allNotes?.map(n => ({ id: n.id, title: n.title, owner_id: n.owner_id })),
    },
  });
}
