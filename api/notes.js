import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { trace, tokenHint, entryHint } from '../src/request-trace.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
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

export default async function handler(request, response) {
  await trace(supabase, { route: request.url?.split('?')[0], method: request.method, kind: 'entry', reason: entryHint(request) });
  response.setHeader('X-Aleph-Resource-Id', 'notes:collection');
  response.setHeader('Cache-Control', 'no-store');

  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'Method not allowed' });
  }

  if (!supabase || !verifyLogin) {
    return response.status(500).json({ error: 'Server configuration unavailable' });
  }

  const login = await verifyLogin(request.headers.authorization);
  if (!login) {
    if (request.headers.authorization) await trace(supabase, { route: request.url?.split('?')[0], method: request.method, kind: 'rejected', status: 401, reason: tokenHint(request.headers.authorization) });
    return response.status(401).json({ error: '로그인이 필요합니다.' });
  }
  if (login.kind === 'judge') await trace(supabase, { route: '/api/notes', method: request.method, kind: login.kind, identity: login.identity, userId: login.userId, reason: 'seen' });

  // [GET] 목록 조회
  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('notes')
      .select('id, title, body, content, owner_id')
      .eq('owner_id', login.userId)
      .order('created_at', { ascending: true });

    if (error) {
      return response.status(500).json({ error: 'Unable to load notes' });
    }

    if (!Array.isArray(data) || data.some(note => note.owner_id !== login.userId)) {
      response.setHeader('X-Aleph-Deny-Reason', 'owner_mismatch');
      return response.status(403).json({ error: '자료 접근 권한이 없습니다.' });
    }

    return response.status(200).json(data.map(note => ({
      id: note.id,
      title: note.title,
      body: note.body ?? note.content ?? '',
    })));
  }

  // [POST] 신규 메모 생성
  const payload = bodyObject(request);
  if (!payload || hasOwnerField(payload)) {
    return response.status(400).json({ error: 'owner_id는 요청 본문에서 지정할 수 없습니다.' });
  }
  const title = payload.title;
  const bodyContent = payload.body ?? payload.content;
  if (!validText(title, 200) || !validText(bodyContent, 5000)) {
    return response.status(400).json({ error: 'title과 body를 확인해 주세요.' });
  }

  const id = payload.id == null || payload.id === '' ? randomUUID() : payload.id;
  if (typeof id !== 'string' || !UUID.test(id)) {
    return response.status(400).json({ error: 'id는 UUID여야 합니다.' });
  }

  const { error } = await supabase
    .from('notes')
    .insert({
      id,
      owner_id: login.userId,
      title: title.trim(),
      body: bodyContent.trim(),
      content: bodyContent.trim(),
    });

  if (error) {
    if (error.code === '23505') {
      return response.status(409).json({ error: '이미 존재하는 id입니다.' });
    }
    return response.status(500).json({ error: 'Unable to create note' });
  }

  return response.status(201).json({ id });
}
