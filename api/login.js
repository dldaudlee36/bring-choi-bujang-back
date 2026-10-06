export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return response.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  let body = request.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }

  const email = body?.email?.trim();
  const password = body?.password;

  if (!email || !password) {
    return response.status(400).json({ error: 'EMAIL_AND_PASSWORD_REQUIRED' });
  }

  try {
    const authRes = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        'apikey': supabaseKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await authRes.json();
    if (!authRes.ok) {
      return response.status(authRes.status || 401).json({
        error: data.error_description || data.msg || data.message || 'LOGIN_FAILED',
      });
    }

    return response.status(200).json({
      access_token: data.access_token,
      user: {
        id: data.user.id,
        email: data.user.email,
      },
    });
  } catch (err) {
    return response.status(500).json({ error: 'AUTH_SERVER_ERROR', message: err.message });
  }
}
