export default function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Aleph-Deny-Reason', 'login_required');
  return response.status(401).json({ error: 'login_required' });
}
