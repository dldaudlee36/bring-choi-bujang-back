import { traceEnv } from '../src/request-trace.mjs';

// Packaging starter only. Implement server-side authentication, official
// NVD/CISA retrieval, six-hour caching, and a fetched-at timestamp.
export default async function handler(_request, response) {
  await traceEnv(_request, '/api/threat-intel');
  response.setHeader('Cache-Control', 'no-store');
  response.status(501).json({ error: 'THREAT_INTEL_NOT_IMPLEMENTED' });
}
