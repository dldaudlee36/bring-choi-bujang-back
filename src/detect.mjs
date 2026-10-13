const WINDOW_MS = 10 * 60 * 1000; // 10분 (600,000ms)
const THRESHOLD = 120; // 120건 초과 시 회수 제안

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // 사용자별(identity.sub) GET 이벤트 필터링 및 시간 분류
  const userEventsMap = new Map();

  for (const event of events) {
    if (event?.method !== 'GET') continue;
    const sub = event?.identity?.sub;
    if (typeof sub !== 'string' || sub.length === 0) continue;

    const atTime = new Date(event?.at).getTime();
    if (Number.isNaN(atTime)) continue;

    if (!userEventsMap.has(sub)) {
      userEventsMap.set(sub, []);
    }
    userEventsMap.get(sub).push(atTime);
  }

  // 각 사용자별 슬라이딩 윈도우 검사 (어느 10분 구간에서든 120건 초과 여부 확인)
  for (const [sub, timestamps] of userEventsMap.entries()) {
    timestamps.sort((a, b) => a - b);

    let left = 0;
    for (let right = 0; right < timestamps.length; right++) {
      while (timestamps[right] - timestamps[left] > WINDOW_MS) {
        left++;
      }
      const countInWindow = right - left + 1;
      if (countInWindow > THRESHOLD) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject: sub,
        };
      }
    }
  }

  return { action: 'observe' };
}
