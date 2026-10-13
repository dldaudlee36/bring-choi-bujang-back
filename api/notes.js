import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
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

function formatNote(record) {
  const rawId = String(record.id);
  const resourceId = rawId.startsWith('note-') || rawId.startsWith('notice-')
    ? rawId
    : `note-${rawId}`;
  return {
    id: rawId,
    resourceId,
    title: record.title,
    body: record.body ?? record.content ?? '',
  };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return response.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  // 1. 요청 토큰 검사 (미로그인 거부)
  const authorization = request.headers.authorization || request.headers['authorization'];
  if (!authorization) {
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  let verifiedUser;
  try {
    const verify = getVerifier(supabaseKey);
    if (!verify) {
      return response.status(500).json({ error: 'VERIFIER_CONFIGURATION_ERROR' });
    }
    verifiedUser = await verify(authorization);
  } catch (_err) {
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  if (!verifiedUser) {
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  // 2. 경로 ID 추출 (/:id) 및 자원 구역(내 메모 vs 강사 공지) 판별
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const pathPart = url.pathname.replace(/^\/api\/notes\/?/i, '').trim();
  const id = request.query?.id || (pathPart ? decodeURIComponent(pathPart) : null);
  const isNotice = typeof id === 'string' && (id.startsWith('notice-') || id === 'notice');
  const dbId = typeof id === 'string' ? id.replace(/^note-/i, '') : id;
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const targetId = typeof dbId === 'string' && UUID_RE.test(dbId) ? dbId : (typeof id === 'string' && UUID_RE.test(id) ? id : null);

  const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const method = request.method;

  try {
    // [강사 공지 자원 처리: notice-]
    if (isNotice) {
      if (method === 'GET') {
        return response.status(200).json({
          id: id || 'notice-instructor-01',
          title: '[강사 공지] 실습 및 구역 보안 안내',
          body: '학생 자료실 메모와 강사 공지는 서로 다른 구역 자원으로 분리 관리됩니다. 학생 계정은 공지를 수정할 수 없습니다.',
        });
      }
      // 강사 공지 수정/삭제/추가 시도 시 강사 권한 검증 (화면 메뉴나 요청 본문·쿼리의 role을 신뢰하지 않음)
      if (method === 'PUT' || method === 'DELETE' || method === 'POST') {
        const isInstructor = verifiedUser.kind === 'instructor' || verifiedUser.role === 'instructor';
        if (!isInstructor) {
          return response.status(403).json({
            error: 'FORBIDDEN',
            reason: 'INSUFFICIENT_ROLE',
            message: '강사 권한이 없습니다.',
          });
        }
      }
    }

    // [GET] 목록 조회 또는 단건 조회
    if (method === 'GET') {
      if (id) {
        if (!targetId) {
          return response.status(404).json({ error: 'NOT_FOUND' });
        }
        // 단건 GET: /api/notes/:id -> { id, title, body }
        const { data, error } = await supabase
          .from('notes')
          .select('*')
          .eq('id', targetId)
          .maybeSingle();

        if (error) {
          return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: error.message });
        }
        if (!data) {
          return response.status(404).json({ error: 'NOT_FOUND' });
        }
        // 타인 메모 접근 차단 (검증된 사용자와 저장된 소유자 대조)
        if (data.owner_id !== verifiedUser.userId) {
          return response.status(403).json({
            error: 'FORBIDDEN',
            reason: 'NOT_OWNER',
            message: '본인 소유의 메모만 접근할 수 있습니다.',
          });
        }
        return response.status(200).json(formatNote(data));
      } else {
        // 목록 GET: /api/notes -> 본인의 메모만 조회 (요청 쿼리의 owner_id나 role은 무시하고 검증된 토큰의 userId로 강제)
        const { data, error } = await supabase
          .from('notes')
          .select('*')
          .eq('owner_id', verifiedUser.userId)
          .order('created_at', { ascending: true });

        if (error) {
          return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: error.message });
        }
        return response.status(200).json((data || []).map(formatNote));
      }
    }

    // [POST] 메모 추가: /api/notes -> { id }
    if (method === 'POST') {
      const body = await parseBody(request);
      const title = body.title?.trim();
      const noteBody = body.body ?? body.content ?? '';

      if (!title) {
        return response.status(400).json({ error: 'TITLE_REQUIRED' });
      }

      // 공지 자원 생성 시도 차단 (요청 본문의 role을 무시하고 토큰 권한 검증)
      const requestedId = (body.id?.trim() || id || '').toLowerCase();
      if (requestedId.startsWith('notice')) {
        const isInstructor = verifiedUser.kind === 'instructor' || verifiedUser.role === 'instructor';
        if (!isInstructor) {
          return response.status(403).json({
            error: 'FORBIDDEN',
            reason: 'INSUFFICIENT_ROLE',
            message: '강사 권한이 없습니다.',
          });
        }
      }

      const rawId = body.id?.trim();
      const cleanId = rawId ? rawId.replace(/^note-/i, '') : null;
      const noteId = (cleanId && UUID_RE.test(cleanId)) ? cleanId : randomUUID();
      // URL·본문의 owner_id나 role을 신뢰하지 않고 검증된 토큰의 사용자 ID로 저장
      let insertData = {
        id: noteId,
        title,
        body: noteBody,
        owner_id: verifiedUser.userId,
      };

      let { error } = await supabase.from('notes').insert([insertData]);
      if (error && error.message?.includes("'body' column")) {
        delete insertData.body;
        insertData.content = noteBody;
        const retry = await supabase.from('notes').insert([insertData]);
        error = retry.error;
      }

      if (error) {
        return response.status(500).json({ error: 'DATABASE_INSERT_ERROR', message: error.message });
      }

      return response.status(201).json({ id: noteId });
    }

    // [PUT] 메모 수정: /api/notes/:id -> { id, title, body }
    if (method === 'PUT') {
      if (!id) {
        return response.status(400).json({ error: 'ID_REQUIRED' });
      }
      if (!targetId) {
        return response.status(404).json({ error: 'NOT_FOUND' });
      }

      const { data: existing, error: findError } = await supabase
        .from('notes')
        .select('*')
        .eq('id', targetId)
        .maybeSingle();

      if (findError) {
        return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: findError.message });
      }
      if (!existing) {
        return response.status(404).json({ error: 'NOT_FOUND' });
      }

      // 기존 행의 저장된 소유자와 검증된 사용자 대조
      if (existing.owner_id !== verifiedUser.userId) {
        return response.status(403).json({
          error: 'FORBIDDEN',
          reason: 'NOT_OWNER',
          message: '본인 소유의 메모만 수정할 수 있습니다.',
        });
      }

      const body = await parseBody(request);

      // 요청 본문이나 쿼리의 role/owner_id 조작 시도 차단
      if (body.owner_id !== undefined && body.owner_id !== verifiedUser.userId) {
        return response.status(403).json({
          error: 'FORBIDDEN',
          reason: 'NOT_OWNER',
          message: '본인 소유의 메모만 수정할 수 있습니다.',
        });
      }
      if (request.query?.owner_id !== undefined && request.query.owner_id !== verifiedUser.userId) {
        return response.status(403).json({
          error: 'FORBIDDEN',
          reason: 'NOT_OWNER',
          message: '본인 소유의 메모만 수정할 수 있습니다.',
        });
      }

      const title = body.title !== undefined ? body.title : existing.title;
      const noteBody = body.body !== undefined ? body.body : (existing.body ?? existing.content ?? '');

      let updateData = {
        title,
        body: noteBody,
        owner_id: verifiedUser.userId,
      };

      let { error: updateError } = await supabase
        .from('notes')
        .update(updateData)
        .eq('id', targetId)
        .eq('owner_id', verifiedUser.userId);

      if (updateError && updateError.message?.includes("'body' column")) {
        delete updateData.body;
        updateData.content = noteBody;
        const retry = await supabase
          .from('notes')
          .update(updateData)
          .eq('id', targetId)
          .eq('owner_id', verifiedUser.userId);
        updateError = retry.error;
      }

      if (updateError) {
        return response.status(500).json({ error: 'DATABASE_UPDATE_ERROR', message: updateError.message });
      }

      return response.status(200).json(formatNote({ id: existing.id, title, body: noteBody }));
    }

    // [DELETE] 메모 삭제: /api/notes/:id
    if (method === 'DELETE') {
      if (!id) {
        return response.status(400).json({ error: 'ID_REQUIRED' });
      }
      if (!targetId) {
        return response.status(404).json({ error: 'NOT_FOUND' });
      }

      const { data: existing, error: findError } = await supabase
        .from('notes')
        .select('id, owner_id')
        .eq('id', targetId)
        .maybeSingle();

      if (findError) {
        return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: findError.message });
      }
      if (!existing) {
        return response.status(404).json({ error: 'NOT_FOUND' });
      }

      // 저장된 소유자와 검증된 사용자 대조 (타인 메모 삭제 차단)
      if (existing.owner_id !== verifiedUser.userId) {
        return response.status(403).json({
          error: 'FORBIDDEN',
          reason: 'NOT_OWNER',
          message: '본인 소유의 메모만 삭제할 수 있습니다.',
        });
      }

      const { error: deleteError } = await supabase
        .from('notes')
        .delete()
        .eq('id', targetId)
        .eq('owner_id', verifiedUser.userId);

      if (deleteError) {
        return response.status(500).json({ error: 'DATABASE_DELETE_ERROR', message: deleteError.message });
      }

      return response.status(200).json({ success: true, id });
    }

    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  } catch (_err) {
    return response.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
  }
}
