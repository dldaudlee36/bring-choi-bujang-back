import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { decide, RULE_IDS } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

// This report contains fixed self-checks, not the engine's 41 attack receipts.
// Never include upstream bodies, tokens, subject IDs, note contents or raw errors.
export async function operationsReport({ config, commit, fetchImpl = fetch }) {
  const checkedAt = new Date().toISOString();
  const reportId = randomUUID();
  const cases = [];
  const probes = [
    ['public_page', 1, 'normal', '/', 'HTTP 200; login page', 'page'],
    ['static_empty', 2, 'forbidden', '/data.json', 'HTTP 200; no public notes', 'empty'],
    ['unauth_list', 3, 'forbidden', '/api/notes', 'HTTP 401; no materials', 'deny'],
    ['forged_identity', 4, 'forbidden', '/api/notes?userId=synthetic_b&role=instructor', 'HTTP 401; no materials', 'deny'],
    ['forged_headers', 4, 'forbidden', '/api/notes', 'HTTP 401; no materials', 'deny', { 'x-user-id': 'synthetic_b', 'x-role': 'instructor' }],
    ['fake_token', 3, 'forbidden', '/api/notes', 'HTTP 401; no materials', 'deny', { Authorization: 'Bearer invalid' }],
    ['unauth_notice', 8, 'forbidden', '/api/notices', 'HTTP 401; no materials', 'deny'],
    ['unauth_restore', 10, 'forbidden', '/api/restore/aabbccdd-1234-4567-89ab-123456789abc', 'HTTP 401; no materials', 'deny', {}, 'POST'],
    ['device_before_approval', 11, 'forbidden', '/api/device/status', 'HTTP 200; approved=false', 'device'],
  ];
  await Promise.all(probes.map(async ([id, stage, type, path, expected, kind, headers = {}, method = 'GET']) => {
    const requestId = randomUUID();
    const row = {
      id, stage, type, source: 'live_api', method, path, expected,
      requestId, checkedAt: new Date().toISOString(), result: 'not_run', observed: 'request_unavailable',
    };
    try {
      const response = await fetchImpl(new URL(path, config.publicAppUrl), {
        method, headers: { Accept: kind === 'page' ? 'text/html' : 'application/json', ...headers },
        redirect: 'error', signal: AbortSignal.timeout(10000),
        alephEvidence: { caseId: id, requestKey: requestId },
      });
      const text = await response.text();
      let body;
      try { body = JSON.parse(text); } catch { /* Never return the raw response. */ }
      const passed = kind === 'page' ? response.status === 200 && text.includes('id="login-form"')
        : kind === 'empty' ? response.status === 200 && Array.isArray(body?.notes) && body.notes.length === 0
        : kind === 'device' ? response.status === 200 && body?.approved === false
        : response.status === 401 && typeof body?.error === 'string' && Object.keys(body).length === 1;
      row.status = response.status;
      row.observed = `HTTP ${response.status}`;
      row.result = passed ? 'matched' : 'mismatch';
      const serverId = response.headers?.get ? response.headers.get('x-vercel-id') : null;
      if (typeof serverId === 'string' && /^[a-z0-9:;=_-]{1,180}$/iu.test(serverId)) row.serverRequestId = serverId;
    } catch { /* No credential-bearing URL or exception message enters the report. */ }
    row.checkedAt = new Date().toISOString();
    cases.push(row);
  }));

  const { normal, suspicious } = fixtureRequests();
  const rules = [
    ['registered_own_read', 6, 'normal', normal, 'allow'],
    ['unregistered_read', 6, 'forbidden', { ...normal, deviceRegistered: false }, 'deny'],
    ['compound_step_up', 7, 'forbidden', suspicious, 'step_up'],
    ['reauthenticated_read', 7, 'normal', { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, 'allow'],
    ['other_zone_read', 8, 'forbidden', { ...normal, subjectId: 'learner_other', path: '/notes/note-fixture', resourceId: 'note-fixture' }, 'deny'],
    ['unknown_path', 8, 'forbidden', { ...normal, path: '/unrecognised' }, 'deny'],
  ];
  for (const [id, stage, type, input, expected] of rules) {
    const requestId = randomUUID();
    const response = await decide({ ...input, requestId });
    cases.push({
      id, stage, type, source: 'synthetic_rule_api', requestId,
      checkedAt: new Date().toISOString(), expected, observed: response.decision,
      reasonCode: response.reasonCode, result: response.decision === expected ? 'matched' : 'mismatch',
    });
  }
  const burst = Array.from({ length: 121 }, (_, i) => ({
    at: new Date(Date.parse(checkedAt) + i * 1000).toISOString(),
    method: 'GET', identity: { sub: 'synthetic_burst' },
  }));
  const detected = detect(burst);
  cases.push({
    id: 'burst_detection', stage: 9, type: 'forbidden', source: 'synthetic_rule_api',
    requestId: randomUUID(), checkedAt: new Date().toISOString(), expected: 'propose_revocation',
    observed: detected.action, result: detected.action === 'propose_revocation' ? 'matched' : 'mismatch',
  });
  // Explicitly unavailable live cases: do not substitute a synthetic pass.
  for (const [id, stage, type, expected] of [
    ['own_authenticated_api', 8, 'normal', 'HTTP 200; own note'],
    ['direct_original_api', 5, 'forbidden', 'original Data API rejects direct access'],
    ['executed_revocation', 9, 'forbidden', 'revoked identity denied'],
    ['verified_restore', 10, 'normal', 'one verified note restored'],
    ['approved_device_api', 11, 'normal', 'registered device reads own note'],
  ]) cases.push({
    id, stage, type, source: 'live_api', expected,
    result: 'not_run', observed: 'verified_runtime_credentials_or_engine_contract_required',
    requestId: null, checkedAt: null,
  });
  cases.sort((a, b) => a.stage - b.stage || a.id.localeCompare(b.id));
  const policyVersion = createHash('sha256').update((await readFile(new URL('./decider.mjs', import.meta.url), 'utf8'))
    .replace(/\r\n/gu, '\n')).digest('hex');
  return {
    schema: 'aleph.operations.v1', step: config.step, commit, checkedAt, reportId,
    sources: {
      student: ['판정기', '탐지 규칙', '접속 앱', '자료실 API', '작전실 자기 점검'],
      engine: 'ALEPH SDP 엔진 사용 · 기기 등록, 요청 검증, 집행과 공식 공격 판정',
      identityProvider: 'Supabase Auth · 사용자 로그인 검증',
    },
    policy: { rules: [...RULE_IDS], version: policyVersion },
    detection: { source: 'synthetic_rule_api', events: burst.length, action: detected.action },
    revocation: { status: 'not_run', reason: 'engine_execution_receipt_unavailable' },
    recovery: { policyVersion, route: config.restoreRoute, status: 'not_run' },
    summary: {
      total: cases.length,
      matched: cases.filter(x => x.result === 'matched').length,
      mismatch: cases.filter(x => x.result === 'mismatch').length,
      notRun: cases.filter(x => x.result === 'not_run').length,
      liveExecuted: cases.filter(x => x.source === 'live_api' && x.result !== 'not_run').length,
      syntheticExecuted: cases.filter(x => x.source === 'synthetic_rule_api').length,
    },
    // The engine's catalogue/receipts have not been imported. These are not self-check totals.
    assault: {
      source: 'ALEPH SDP engine', total: 41, executed: 0, blocked: 0, notRun: 41,
      status: 'not_run', reason: 'official_attack_receipts_not_connected',
    },
    cases,
  };
}
