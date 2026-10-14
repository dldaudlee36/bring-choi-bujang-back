import config from '../aleph.config.json' with { type: 'json' };
import { operationsReport } from '../src/operations-report.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'method_not_allowed' });
  }
  if (request.url?.includes('?')) return response.status(400).json({ error: 'unexpected_query' });
  try {
    return response.status(200).json(await operationsReport({
      config,
      commit: process.env.VERCEL_GIT_COMMIT_SHA ?? null,
    }));
  } catch {
    return response.status(503).json({ error: 'checks_unavailable' });
  }
}
