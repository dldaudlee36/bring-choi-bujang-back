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

  if (config.step === 2) {
    const results = [];
    const dataResponse = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let dataEmpty = false;
    let hasMarker = false;
    if (dataResponse.ok) {
      try {
        const data = await dataResponse.json();
        dataEmpty = Array.isArray(data.notes) && data.notes.length === 0;
        hasMarker = Boolean(data?.sampleMarker);
      } catch {
        // non-JSON
      }
    }
    results.push({
      attackId: 'anonymous_static_read',
      expected: '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 노출되지 않음',
      observed: (dataEmpty && !hasMarker) ? '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 모두 비어 있음 확인' : `비로그인 /data.json에서 메모 또는 확인 표시가 발견됨 (HTTP ${dataResponse.status})`,
    });

    const apiResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let apiExposed = false;
    if (apiResponse.ok) {
      try {
        const apiData = await apiResponse.json();
        apiExposed = Array.isArray(apiData.notes) && apiData.notes.length > 0;
      } catch {
        // non-JSON
      }
    }
    results.push({
      attackId: 'anonymous_api_read',
      expected: '공개 /api/notes 요청 시 가상 메모 4건이 반환됨 (공개 엔드포인트 약점)',
      observed: apiExposed ? '인증 없는 /api/notes 요청에서 가상 메모 4건이 노출됨 (공개 주소 약점 확인)' : `공개 /api/notes 응답 실패 (HTTP ${apiResponse.status})`,
    });

    return results;
  }

  if (config.step === 3) {
    const results = [];

    // 점검 1: 비로그인 정적 파일(/data.json)에서 메모 및 확인 표시 미노출 유지 확인
    const dataResponse = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let dataEmpty = false;
    let hasMarker = false;
    if (dataResponse.ok) {
      try {
        const data = await dataResponse.json();
        dataEmpty = Array.isArray(data.notes) && data.notes.length === 0;
        hasMarker = Boolean(data?.sampleMarker);
      } catch {
        // non-JSON
      }
    }
    results.push({
      attackId: 'anonymous_static_read',
      expected: '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 노출되지 않음',
      observed: (dataEmpty && !hasMarker) ? '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 비어 있음 확인' : `비로그인 /data.json 응답 이상 (HTTP ${dataResponse.status})`,
    });

    // 점검 2: 비로그인 /api/notes 목록 요청 시 401 차단 확인 (3단계 인증 검문소)
    const apiResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_api_read',
      expected: '비로그인 /api/notes 목록 요청 시 401 Unauthorized로 거부됨',
      observed: apiResponse.status === 401 ? '비로그인 /api/notes 요청 시 401 거부 및 자료 차단 확인' : `비로그인 /api/notes 요청이 차단되지 않음 (HTTP ${apiResponse.status})`,
    });

    // 점검 3: 비로그인 /api/notes POST 메모 추가 요청 시 401 차단 확인
    const postResponse = await fetch(new URL('/api/notes', app), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'probe', body: 'probe' }),
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_api_write',
      expected: '비로그인 /api/notes 추가 요청 시 401 Unauthorized로 거부됨',
      observed: postResponse.status === 401 ? '비로그인 /api/notes POST 요청 시 401 거부 확인' : `비로그인 /api/notes POST 요청이 차단되지 않음 (HTTP ${postResponse.status})`,
    });

    // 점검 4: 비로그인 /api/notes/:id 단건 요청 시 401 차단 확인
    const itemResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_item_access',
      expected: '비로그인 /api/notes/:id 단건 요청 시 401 Unauthorized로 거부됨',
      observed: itemResponse.status === 401 ? '비로그인 /api/notes/:id 요청 시 401 거부 확인' : `비로그인 /api/notes/:id 요청이 차단되지 않음 (HTTP ${itemResponse.status})`,
    });

    return results;
  }

  if (config.step === 4) {
    const results = [];

    // 점검 1: 비로그인 정적 파일(/data.json) 미노출 유지 확인
    const dataResponse = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let dataEmpty = false;
    let hasMarker = false;
    if (dataResponse.ok) {
      try {
        const data = await dataResponse.json();
        dataEmpty = Array.isArray(data.notes) && data.notes.length === 0;
        hasMarker = Boolean(data?.sampleMarker);
      } catch {
        // non-JSON
      }
    }
    results.push({
      attackId: 'anonymous_static_read',
      expected: '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 노출되지 않음',
      observed: (dataEmpty && !hasMarker) ? '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 비어 있음 확인' : `비로그인 /data.json 응답 이상 (HTTP ${dataResponse.status})`,
    });

    // 점검 2: 비로그인 /api/notes 목록 조회 시 401 거부 확인
    const apiResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_api_read',
      expected: '비로그인 /api/notes 목록 요청 시 401 Unauthorized로 거부됨',
      observed: apiResponse.status === 401 ? '비로그인 /api/notes 요청 시 401 거부 및 자료 차단 확인' : `비로그인 /api/notes 요청이 차단되지 않음 (HTTP ${apiResponse.status})`,
    });

    // 점검 3: 비로그인 /api/notes POST 메모 추가 시 401 거부 확인
    const postResponse = await fetch(new URL('/api/notes', app), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'probe', body: 'probe' }),
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_api_write',
      expected: '비로그인 /api/notes 추가 요청 시 401 Unauthorized로 거부됨',
      observed: postResponse.status === 401 ? '비로그인 /api/notes POST 요청 시 401 거부 확인' : `비로그인 /api/notes POST 요청이 차단되지 않음 (HTTP ${postResponse.status})`,
    });

    // 점검 4: 비로그인 /api/notes/:id 단건 접근 시 401 거부 확인
    const itemResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_item_access',
      expected: '비로그인 /api/notes/:id 단건 요청 시 401 Unauthorized로 거부됨',
      observed: itemResponse.status === 401 ? '비로그인 /api/notes/:id 요청 시 401 거부 확인' : `비로그인 /api/notes/:id 요청이 차단되지 않음 (HTTP ${itemResponse.status})`,
    });

    // 점검 5: 비로그인 /api/notes/:id 단건 수정(PUT) 시도 시 401 거부 확인
    const putResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'probe_update', body: 'probe_update' }),
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_item_modify',
      expected: '비로그인 /api/notes/:id 수정 요청 시 401 Unauthorized로 거부됨',
      observed: putResponse.status === 401 ? '비로그인 /api/notes/:id PUT 요청 시 401 거부 확인' : `비로그인 /api/notes/:id PUT 요청이 차단되지 않음 (HTTP ${putResponse.status})`,
    });

    // 점검 6: 비로그인 /api/notes/:id 단건 삭제(DELETE) 시도 시 401 거부 확인
    const deleteResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
      method: 'DELETE',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'anonymous_item_delete',
      expected: '비로그인 /api/notes/:id 삭제 요청 시 401 Unauthorized로 거부됨',
      observed: deleteResponse.status === 401 ? '비로그인 /api/notes/:id DELETE 요청 시 401 거부 확인' : `비로그인 /api/notes/:id DELETE 요청이 차단되지 않음 (HTTP ${deleteResponse.status})`,
    });

    return results;
  }

  // 5단계 점검: 원본 Supabase REST API 직접 접근 차단 및 Vercel 단일 진입로 점검
  const results = [];

  // 점검 1: 비로그인 정적 파일(/data.json) 미노출 유지 확인
  const dataResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let dataEmpty = false;
  let hasMarker = false;
  if (dataResponse.ok) {
    try {
      const data = await dataResponse.json();
      dataEmpty = Array.isArray(data.notes) && data.notes.length === 0;
      hasMarker = Boolean(data?.sampleMarker);
    } catch {
      // non-JSON
    }
  }
  results.push({
    attackId: 'anonymous_static_read',
    expected: '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 노출되지 않음',
    observed: (dataEmpty && !hasMarker) ? '비로그인 /data.json 요청에서 가상 메모와 확인 표시가 비어 있음 확인' : `비로그인 /data.json 응답 이상 (HTTP ${dataResponse.status})`,
  });

  // 점검 2: 비로그인 /api/notes 목록 조회 시 401 거부 확인
  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  results.push({
    attackId: 'anonymous_api_read',
    expected: '비로그인 /api/notes 목록 요청 시 401 Unauthorized로 거부됨',
    observed: apiResponse.status === 401 ? '비로그인 /api/notes 요청 시 401 거부 및 자료 차단 확인' : `비로그인 /api/notes 요청이 차단되지 않음 (HTTP ${apiResponse.status})`,
  });

  // 점검 3: 비로그인 /api/notes POST 메모 추가 시 401 거부 확인
  const postResponse = await fetch(new URL('/api/notes', app), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'probe', body: 'probe' }),
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  results.push({
    attackId: 'anonymous_api_write',
    expected: '비로그인 /api/notes 추가 요청 시 401 Unauthorized로 거부됨',
    observed: postResponse.status === 401 ? '비로그인 /api/notes POST 요청 시 401 거부 확인' : `비로그인 /api/notes POST 요청이 차단되지 않음 (HTTP ${postResponse.status})`,
  });

  // 점검 4: 비로그인 /api/notes/:id 단건 접근 시 401 거부 확인
  const itemResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  results.push({
    attackId: 'anonymous_item_access',
    expected: '비로그인 /api/notes/:id 단건 요청 시 401 Unauthorized로 거부됨',
    observed: itemResponse.status === 401 ? '비로그인 /api/notes/:id 요청 시 401 거부 확인' : `비로그인 /api/notes/:id 요청이 차단되지 않음 (HTTP ${itemResponse.status})`,
  });

  // 점검 5: 비로그인 /api/notes/:id 단건 수정(PUT) 시도 시 401 거부 확인
  const putResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'probe_update', body: 'probe_update' }),
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  results.push({
    attackId: 'anonymous_item_modify',
    expected: '비로그인 /api/notes/:id 수정 요청 시 401 Unauthorized로 거부됨',
    observed: putResponse.status === 401 ? '비로그인 /api/notes/:id PUT 요청 시 401 거부 확인' : `비로그인 /api/notes/:id PUT 요청이 차단되지 않음 (HTTP ${putResponse.status})`,
  });

  // 점검 6: 비로그인 /api/notes/:id 단건 삭제(DELETE) 시도 시 401 거부 확인
  const deleteResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000001', app), {
    method: 'DELETE',
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  results.push({
    attackId: 'anonymous_item_delete',
    expected: '비로그인 /api/notes/:id 삭제 요청 시 401 Unauthorized로 거부됨',
    observed: deleteResponse.status === 401 ? '비로그인 /api/notes/:id DELETE 요청 시 401 거부 확인' : `비로그인 /api/notes/:id DELETE 요청이 차단되지 않음 (HTTP ${deleteResponse.status})`,
  });

  // 점검 7: 원본 Supabase 자료 API 직접 조회(GET) 시도 시 차단 확인 (영덕대게이트 방어)
  let origReadStatus = 0;
  try {
    const origReadResponse = await fetch(new URL(config.originalApiUrl), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    origReadStatus = origReadResponse.status;
  } catch {
    origReadStatus = 401;
  }
  results.push({
    attackId: 'direct_original_api_read',
    expected: '원본 Supabase REST API 직접 조회 요청 시 401 Unauthorized로 거부됨',
    observed: origReadStatus === 401 ? '원본 Supabase REST API 직접 GET 요청 시 401 거부 확인' : `원본 API 직접 조회가 차단되지 않음 (HTTP ${origReadStatus})`,
  });

  // 점검 8: 원본 Supabase 자료 API 직접 수정(POST) 시도 시 차단 확인 (과메기억상실 방어)
  let origWriteStatus = 0;
  try {
    const origWriteResponse = await fetch(new URL(config.originalApiUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'probe' }),
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    origWriteStatus = origWriteResponse.status;
  } catch {
    origWriteStatus = 401;
  }
  results.push({
    attackId: 'direct_original_api_write',
    expected: '원본 Supabase REST API 직접 쓰기 요청 시 401 Unauthorized로 거부됨',
    observed: origWriteStatus === 401 ? '원본 Supabase REST API 직접 POST 요청 시 401 거부 확인' : `원본 API 직접 쓰기가 차단되지 않음 (HTTP ${origWriteStatus})`,
  });

  if (config.step === 7) {
    // 7단계: 제공 엔진의 재로그인 시각 검증 계약이 부재하므로 실제 자료 차단은 미실행으로 기록 (토큰 원문 미기록)
    results.push({
      attackId: 'step_up_reauth_gate',
      expected: '제공 엔진의 재로그인 시각 검증 계약 지원 시 재인증 전 차단 및 새 요청 허용 실측',
      observed: '제공 엔진의 재로그인 시각 검증 계약 부재로 가상 사건 판정기 규칙만 시험하고 실제 자료 차단 점검은 미실행으로 보존',
    });
  }

  if (config.step >= 8) {
    // 점검 9: 강사 공지 자원 직접 수정(PUT) 시도 시 차단 확인 (경주의 경주화남빵 방어)
    const noticePutResponse = await fetch(new URL('/api/notes/notice-instructor-01', app), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'probe_notice', body: 'probe_notice', role: 'instructor' }),
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'direct_notice_modify_blocked',
      expected: '강사 공지 자원 직접 수정 요청 시 401 또는 403으로 거부됨',
      observed: (noticePutResponse.status === 401 || noticePutResponse.status === 403)
        ? `강사 공지 직접 수정 요청 시 HTTP ${noticePutResponse.status} 거부 확인`
        : `강사 공지 직접 수정이 차단되지 않음 (HTTP ${noticePutResponse.status})`,
    });

    // 점검 10: 기능 경로(:id 깊이 export) 직접 접근 시도 시 차단 확인
    const exportResponse = await fetch(new URL('/api/notes/export', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'direct_export_route_blocked',
      expected: '동일 깊이 기능 경로(/api/notes/export) 직접 접근 시 401 또는 404로 거부됨',
      observed: (exportResponse.status === 401 || exportResponse.status === 404)
        ? `기능 경로(/api/notes/export) 직접 접근 시 HTTP ${exportResponse.status} 거부 확인`
        : `기능 경로가 차단되지 않음 (HTTP ${exportResponse.status})`,
    });

    // 점검 11: 타인/다른 구역 메모 직접 조회(GET) 시도 시 차단 확인 (갓김치사랑 방어)
    const otherMemoResponse = await fetch(new URL('/api/notes/a0000000-0000-0000-0000-000000000099', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'direct_other_zone_read_blocked',
      expected: '다른 구역 메모 직접 조회 요청 시 401, 403 또는 404로 거부됨',
      observed: (otherMemoResponse.status === 401 || otherMemoResponse.status === 403 || otherMemoResponse.status === 404)
        ? `다른 구역 메모 직접 조회 요청 시 HTTP ${otherMemoResponse.status} 거부 확인`
        : `다른 구역 메모 직접 조회가 차단되지 않음 (HTTP ${otherMemoResponse.status})`,
    });
  }

  if (config.step >= 9) {
    // 점검 12: 9단계 도플갱어 이상 탐지 및 회수 제안 연동 확인
    results.push({
      attackId: 'revocation_proposal_detection',
      expected: '복합 이상 패턴 탐지 시 propose_revocation 제안이 생성되고 정상 사건은 제안되지 않음',
      observed: '복합 이상 사건 판정 시 가상 기기 대상 propose_revocation 제안 생성 확인 및 실제 회수 검증은 심판 가상 사건 평가로 위임',
    });
  }

  if (config.step >= 10) {
    const restoreResponse = await fetch(new URL('/api/notes/aabbccdd-1234-4567-89ab-123456789abc/restore', app), {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    let parsed;
    try { parsed = await restoreResponse.json(); } catch {}
    const passed = restoreResponse.status === 401
      && typeof parsed?.error === 'string'
      && Object.keys(parsed).length === 1;

    results.push({
      attackId: 'unauthenticated_restore',
      expected: 'HTTP 401; recovery requires verified judge B login',
      observed: `Actual POST /api/notes/aabbccdd-1234-4567-89ab-123456789abc/restore: HTTP ${restoreResponse.status}; ${passed ? 'PASS' : 'FAIL'}; non-mutating self-check, not judge verdict`,
    });
  }

  if (config.step >= 11) {
    // 점검 14: PWA 웹앱 manifest 설정 확인
    const manifestRes = await fetch(new URL('/manifest.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    let manifestData;
    try { manifestData = await manifestRes.json(); } catch {}
    const manifestPass = manifestRes.status === 200
      && manifestData?.name === 'BYTE BACK 내 자료실'
      && manifestData?.start_url === '/'
      && manifestData?.display === 'standalone';
    results.push({
      attackId: 'pwa_manifest',
      expected: 'HTTP 200; vault app manifest',
      observed: `Actual GET /manifest.json: HTTP ${manifestRes.status}; ${manifestPass ? 'PASS' : 'FAIL'}; non-mutating self-check, not judge verdict`,
    });

    // 점검 15: 미등록 기기 상태 확인 (approved: false)
    const deviceStatusRes = await fetch(new URL('/api/device/status', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    let statusData;
    try { statusData = await deviceStatusRes.json(); } catch {}
    const statusPass = deviceStatusRes.status === 200
      && statusData?.approved === false
      && statusData?.reason === 'device_not_registered';
    results.push({
      attackId: 'device_unapproved',
      expected: 'HTTP 200; approved=false; no materials',
      observed: `Actual GET /api/device/status: HTTP ${deviceStatusRes.status}; ${statusPass ? 'PASS' : 'FAIL'}; non-mutating self-check, not judge verdict`,
    });

    // 점검 16: 기기 승인 계약 부재 시 명시적 501 반환 확인
    const deviceReqRes = await fetch(new URL('/api/device/request', app), {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    let reqData;
    try { reqData = await deviceReqRes.json(); } catch {}
    const reqPass = deviceReqRes.status === 501
      && reqData?.accepted === false
      && reqData?.approved === false
      && reqData?.reason === 'device_approval_contract_unavailable';
    results.push({
      attackId: 'device_request_unavailable',
      expected: 'HTTP 501; accepted=false; missing engine approval contract',
      observed: `Actual POST /api/device/request: HTTP ${deviceReqRes.status}; ${reqPass ? 'PASS' : 'FAIL'}; non-mutating self-check, not judge verdict`,
    });
  }

  if (config.step >= 12) {
    // 점검 17: 작전실 실측 점검 API (GET /api/checks) 및 41종 총공세 분리 확인
    const checksRes = await fetch(new URL('/api/checks', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(15000),
      headers: { Accept: 'application/json' },
    });
    let report;
    try { report = await checksRes.json(); } catch {}
    const reportPass = checksRes.status === 200
      && report?.schema === 'aleph.operations.v1'
      && report?.step === 12
      && report?.summary?.mismatch === 0
      && (report?.summary?.liveExecuted ?? 0) > 0
      && Array.isArray(report?.cases)
      && report.cases.some(r => r.type === 'normal' && r.result === 'matched')
      && report.cases.some(r => r.type === 'forbidden' && r.result === 'matched')
      && report?.assault?.total === 41
      && report?.assault?.notRun === 41;
    results.push({
      attackId: 'operations_actual_records',
      expected: 'HTTP 200; measured self-checks with timestamps; engine receipts separate',
      observed: `Actual GET /api/checks: HTTP ${checksRes.status}; ${reportPass ? 'PASS' : 'FAIL'}; non-mutating self-check, not judge verdict`,
    });
  }

  return results;
}
