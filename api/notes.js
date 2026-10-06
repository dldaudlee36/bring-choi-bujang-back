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

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET') {
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return response.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  const authorization = request.headers.authorization || request.headers['authorization'];
  if (!authorization) {
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  try {
    const verify = getVerifier(supabaseKey);
    if (!verify) {
      return response.status(500).json({ error: 'VERIFIER_CONFIGURATION_ERROR' });
    }

    const verifiedUser = await verify(authorization);
    if (!verifiedUser) {
      return response.status(401).json({ error: 'UNAUTHORIZED' });
    }

    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const { data, error } = await supabase
      .from('notes')
      .select('title, content')
      .order('id', { ascending: true });

    if (error) {
      return response.status(500).json({ error: 'DATABASE_QUERY_ERROR' });
    }

    return response.status(200).json({ notes: data || [] });
  } catch (_err) {
    return response.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
  }
}
