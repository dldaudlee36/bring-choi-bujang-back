// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
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

  const results = [];

  // 점검 1: /data.json 정적 파일에서 메모가 제거되었는지
  const dataResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let dataEmpty = false;
  if (dataResponse.ok) {
    try {
      const data = await dataResponse.json();
      dataEmpty = Array.isArray(data.notes) && data.notes.length === 0;
    } catch {
      // non-JSON
    }
  }
  results.push({
    attackId: 'anonymous_static_read',
    expected: '비로그인 /data.json 요청에서 가상 메모가 노출되지 않음',
    observed: dataEmpty ? '비로그인 /data.json 요청에서 가상 메모가 비어 있음 확인' : `비로그인 /data.json에서 가상 메모가 발견됨 (HTTP ${dataResponse.status})`,
  });

  // 점검 2: /api/notes 공개 서버 함수 호출 점검 (현재의 공개 주소 약점 점검)
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
