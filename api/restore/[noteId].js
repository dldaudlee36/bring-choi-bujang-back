import { createClient } from '@supabase/supabase-js';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { createRestoreHandler } from '../../src/restore-api.mjs';

let config;
try {
  config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
} catch {
  config = null;
}

const secret = process.env.SUPABASE_SECRET_KEY;
const url = process.env.SUPABASE_URL;

export default createRestoreHandler({
  db: url && secret ? createClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } }) : null,
  verifyLogin: secret ? createLoginVerifier({ config, supabaseSecretKey: secret }) : null,
});
