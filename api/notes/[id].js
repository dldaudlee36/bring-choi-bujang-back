import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

const supabase = supabaseUrl && supabaseSecretKey
  ? createClient(supabaseUrl, supabaseSecretKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

const verifyLogin = supabaseSecretKey
  ? createLoginVerifier({ config, supabaseSecretKey })
  : null;

function bodyObject(request) {
  if (!request.body) return {};
  if (typeof request.body === 'object') return request.body;
  if (typeof request.body === 'string') {
    try { return JSON.parse(request.body); } catch { return null; }
  }
  return null;
}

function validText(value, max) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= max;
}

function hasOwnerField(payload) {
  return payload && (
    Object.prototype.hasOwnProperty.call(payload, 'owner_id')
    || Object.prototype.hasOwnProperty.call(payload, 'ownerId')
  );
}

function noteResponse(note) {
  return {
    id: note.id,
    title: note.title,
    body: note.body ?? note.content ?? '',
  };
}

function extractId(request) {
  if (typeof request.url !== 'string') return null;
  let url;
  try { url = new URL(request.url, 'https://api.invalid'); } catch { return null; }
  const segments = url.pathname.split('/').filter(Boolean);
  const raw = segments[segments.length - 1];
  if (!raw || !UUID_RE.test(raw)) return null;
  return raw.toLowerCase();
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return response.status(405).json({ error: 'Method not allowed' });
  }

  if (!supabase || !verifyLogin) {
    return response.status(500).json({ error: 'Server configuration unavailable' });
  }

  const login = await verifyLogin(request.headers.authorization);
  if (!login) {
    return response.status(401).json({ error: '로그인이 필요합니다.' });
  }

  const rawId = extractId(request);
  if (!rawId) {
    response.setHeader('X-Aleph-Deny-Reason', 'invalid_resource_path');
    return response.status(400).json({ error: '올바른 메모 UUID가 필요합니다.' });
  }

  response.setHeader('X-Aleph-Resource-Id', 'notes:' + rawId);

  // [GET] 단건 조회
  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('notes')
      .select('id, title, body, content, owner_id')
      .eq('id', rawId)
      .eq('owner_id', login.userId)
      .maybeSingle();

    if (error) return response.status(500).json({ error: 'Unable to load note' });
    if (!data || data.owner_id !== login.userId) {
      response.setHeader('X-Aleph-Deny-Reason', 'not_found_or_not_owned');
      return response.status(404).json({ error: '메모를 찾을 수 없습니다.' });
    }
    return response.status(200).json(noteResponse(data));
  }

  // [PUT] 메모 변조/수정 (닭크웹 침해 테스트 시 호출됨)
  if (request.method === 'PUT') {
    const payload = bodyObject(request);
    if (!payload || hasOwnerField(payload)) {
      return response.status(400).json({ error: 'owner_id는 수정할 수 없습니다.' });
    }
    const title = payload.title;
    const bodyContent = payload.body ?? payload.content;
    if (!validText(title, 200) || !validText(bodyContent, 5000)) {
      return response.status(400).json({ error: 'title과 body를 확인해 주세요.' });
    }

    const { data: existing, error: existingError } = await supabase
      .from('notes')
      .select('id, owner_id')
      .eq('id', rawId)
      .eq('owner_id', login.userId)
      .maybeSingle();

    if (existingError) return response.status(500).json({ error: 'Unable to load note' });
    if (!existing || existing.owner_id !== login.userId) {
      response.setHeader('X-Aleph-Deny-Reason', 'not_found_or_not_owned');
      return response.status(404).json({ error: '메모를 찾을 수 없습니다.' });
    }

    const { data, error } = await supabase
      .from('notes')
      .update({
        title: title.trim(),
        body: bodyContent.trim(),
        content: bodyContent.trim(),
      })
      .eq('id', rawId)
      .eq('owner_id', login.userId)
      .select('id, title, body, content, owner_id')
      .maybeSingle();

    if (error) return response.status(500).json({ error: 'Unable to update note' });
    if (!data || data.owner_id !== login.userId) {
      response.setHeader('X-Aleph-Deny-Reason', 'not_found_or_not_owned');
      return response.status(404).json({ error: '메모를 찾을 수 없습니다.' });
    }
    return response.status(200).json(noteResponse(data));
  }

  // [DELETE] 메모 삭제
  const { data, error } = await supabase
    .from('notes')
    .delete()
    .eq('id', rawId)
    .eq('owner_id', login.userId)
    .select('id, owner_id')
    .maybeSingle();

  if (error) return response.status(500).json({ error: 'Unable to delete note' });
  if (!data || data.owner_id !== login.userId) {
    response.setHeader('X-Aleph-Deny-Reason', 'not_found_or_not_owned');
    return response.status(404).json({ error: '메모를 찾을 수 없습니다.' });
  }
  return response.status(204).end();
}
