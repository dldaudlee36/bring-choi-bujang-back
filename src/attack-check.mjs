// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step < 1 || config.step > 12) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (config.step === 1) {
    if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  const base = app;
  const results = [];
  const checks = [
    { attackId: 'public_page', path: '/', expected: 'HTTP 200; existing login page', kind: 'page' },
    { attackId: 'public_data_empty', path: '/data.json', expected: 'HTTP 200; notes is an empty array', kind: 'data' },
    { attackId: 'unauthenticated_notes', path: '/api/notes', expected: 'HTTP 401; JSON error without notes', kind: 'deny' },
  ];
  if (config.step >= 10) checks.push({
    attackId: 'unauthenticated_restore', method: 'POST',
    path: '/api/restore/aabbccdd-1234-4567-89ab-123456789abc',
    expected: 'HTTP 401; recovery requires verified judge B login', kind: 'deny',
  });
  if (config.step >= 11) checks.push(
    { attackId: 'pwa_manifest', path: '/manifest.json', expected: 'HTTP 200; vault app manifest', kind: 'manifest' },
    { attackId: 'device_unapproved', path: '/api/device/status', expected: 'HTTP 200; approved=false; no materials', kind: 'device' },
    { attackId: 'device_request_unavailable', method: 'POST', path: '/api/device/request',
      expected: 'HTTP 501; accepted=false; missing engine approval contract', kind: 'request' },
  );
  if (config.step >= 12) checks.push({
    attackId: 'operations_actual_records', path: '/api/checks',
    expected: 'HTTP 200; measured self-checks with timestamps; engine receipts separate', kind: 'operations'
  });

  for (const check of checks) {
    if (check.method && check.method !== 'GET' && check.method !== 'HEAD') {
      results.push({
        attackId: check.attackId,
        expected: check.expected,
        observed: 'not_run',
      });
      continue;
    }
    const response = await fetch(new URL(check.path, base), {
      redirect: 'error', signal: AbortSignal.timeout(15000),
      method: check.method ?? 'GET',
      headers: { Accept: check.kind === 'page' ? 'text/html' : 'application/json' },
    });
    const body = await response.text();
    let passed = false;
    if (check.kind === 'page') passed = response.status === 200 && body.includes('id="login-form"');
    else {
      let parsed;
      try { parsed = JSON.parse(body); } catch { /* Report failure without recording body. */ }
      if (check.kind === 'data') passed = response.status === 200 && Array.isArray(parsed?.notes) && parsed.notes.length === 0;
      else if (check.kind === 'manifest') passed = response.status === 200
        && parsed?.name === 'BYTE BACK 내 자료실' && parsed?.start_url === '/' && parsed?.display === 'standalone';
      else if (check.kind === 'device') passed = response.status === 200
        && parsed?.approved === false && parsed?.reason === 'device_not_registered';
      else if (check.kind === 'request') passed = response.status === 501
        && parsed?.accepted === false && parsed?.approved === false
        && parsed?.reason === 'device_approval_contract_unavailable';
      else if (check.kind === 'operations') passed = response.status === 200
        && parsed?.schema === 'aleph.operations.v1' && parsed?.step === 12
        && parsed?.summary?.mismatch === 0 && parsed?.summary?.liveExecuted > 0
        && Array.isArray(parsed?.cases) && parsed.cases.some(row => row.type === 'normal' && row.result === 'matched')
        && parsed.cases.some(row => row.type === 'forbidden' && row.result === 'matched')
        && parsed?.assault?.total === 41 && parsed?.assault?.notRun === 41;
      else passed = response.status === 401 && typeof parsed?.error === 'string'
        && Object.keys(parsed).length === 1;
    }
    results.push({
      attackId: check.attackId,
      expected: check.expected,
      observed: `Actual ${check.method ?? 'GET'} ${check.path}: HTTP ${response.status}; ${passed ? 'PASS' : 'FAIL'}; non-mutating self-check, not judge verdict`
    });
  }

  return results;
}
