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
  return {
    id: String(record.id),
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

  // 2. 경로 ID 추출 (/:id)
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const pathPart = url.pathname.replace(/^\/api\/notes\/?/i, '').trim();
  const id = request.query?.id || (pathPart ? decodeURIComponent(pathPart) : null);

  const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const method = request.method;

  try {
    // [GET] 목록 조회 또는 단건 조회
    if (method === 'GET') {
      if (id) {
        // 단건 GET: /api/notes/:id -> { id, title, body }
        const { data, error } = await supabase
          .from('notes')
          .select('*')
          .eq('id', id)
          .maybeSingle();

        if (error) {
          return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: error.message });
        }
        if (!data) {
          return response.status(404).json({ error: 'NOT_FOUND' });
        }
        // 타인 메모 접근 차단 (본인 확인)
        if (data.owner_id !== verifiedUser.userId) {
          return response.status(403).json({ error: 'FORBIDDEN' });
        }
        return response.status(200).json(formatNote(data));
      } else {
        // 목록 GET: /api/notes -> 본인의 메모만 조회
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

      const noteId = body.id?.trim() || randomUUID();
      // URL·본문의 owner_id를 신뢰하지 않고 검증된 토큰의 사용자 ID로 저장
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

      const { data: existing, error: findError } = await supabase
        .from('notes')
        .select('*')
        .eq('id', id)
        .maybeSingle();

      if (findError) {
        return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: findError.message });
      }
      if (!existing) {
        return response.status(404).json({ error: 'NOT_FOUND' });
      }

      // 기존 행의 소유자가 본인인지 확인
      if (existing.owner_id !== verifiedUser.userId) {
        return response.status(403).json({ error: 'FORBIDDEN' });
      }

      const body = await parseBody(request);

      // 새 행의 소유자 확인 (소유자 변경 시도 차단)
      if (body.owner_id !== undefined && body.owner_id !== verifiedUser.userId) {
        return response.status(403).json({ error: 'FORBIDDEN' });
      }
      if (request.query?.owner_id !== undefined && request.query.owner_id !== verifiedUser.userId) {
        return response.status(403).json({ error: 'FORBIDDEN' });
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
        .eq('id', id)
        .eq('owner_id', verifiedUser.userId);

      if (updateError && updateError.message?.includes("'body' column")) {
        delete updateData.body;
        updateData.content = noteBody;
        const retry = await supabase
          .from('notes')
          .update(updateData)
          .eq('id', id)
          .eq('owner_id', verifiedUser.userId);
        updateError = retry.error;
      }

      if (updateError) {
        return response.status(500).json({ error: 'DATABASE_UPDATE_ERROR', message: updateError.message });
      }

      return response.status(200).json({ id, title, body: noteBody });
    }

    // [DELETE] 메모 삭제: /api/notes/:id
    if (method === 'DELETE') {
      if (!id) {
        return response.status(400).json({ error: 'ID_REQUIRED' });
      }

      const { data: existing, error: findError } = await supabase
        .from('notes')
        .select('id, owner_id')
        .eq('id', id)
        .maybeSingle();

      if (findError) {
        return response.status(500).json({ error: 'DATABASE_QUERY_ERROR', message: findError.message });
      }
      if (!existing) {
        return response.status(404).json({ error: 'NOT_FOUND' });
      }

      // 소유자가 본인인지 확인 (타인 메모 삭제 차단)
      if (existing.owner_id !== verifiedUser.userId) {
        return response.status(403).json({ error: 'FORBIDDEN' });
      }

      const { error: deleteError } = await supabase
        .from('notes')
        .delete()
        .eq('id', id)
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
