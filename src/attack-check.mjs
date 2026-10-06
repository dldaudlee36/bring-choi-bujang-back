// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2 && config.step !== 3) {
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

  // 3단계 점검
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
