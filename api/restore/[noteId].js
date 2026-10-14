import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { createRestoreHandler } from '../../src/restore-api.mjs';
import '../../src/decider.mjs';

const secret = process.env.SUPABASE_SECRET_KEY;
const url = process.env.SUPABASE_URL;

export default createRestoreHandler({
  db: url && secret ? createClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } }) : null,
  verifyLogin: secret ? createLoginVerifier({ config, supabaseSecretKey: secret }) : null,
});
