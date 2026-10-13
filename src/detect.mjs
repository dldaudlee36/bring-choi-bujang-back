// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // 사용자/기기별로 GET 사건 분류
  const userEventsMap = new Map();

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    // GET 요청만 검사 (method가 명시된 경우 GET이어야 함)
    if (event.method && typeof event.method === 'string' && event.method.toUpperCase() !== 'GET') {
      continue;
    }

    // 대상 식별자 추출 (identity.sub, deviceId, subject 등)
    const subject = (event.identity && typeof event.identity.sub === 'string' && event.identity.sub.trim())
      || (typeof event.deviceId === 'string' && event.deviceId.trim())
      || (typeof event.subject === 'string' && event.subject.trim())
      || (typeof event.sub === 'string' && event.sub.trim())
      || null;

    if (!subject) continue;

    const time = Date.parse(event.at);
    if (Number.isNaN(time)) continue;

    if (!userEventsMap.has(subject)) {
      userEventsMap.set(subject, []);
    }
    userEventsMap.get(subject).push(time);
  }

  const WINDOW_MS = 10 * 60 * 1000; // 10분 구간 (600,000ms)
  const THRESHOLD = 120; // 120건을 넘을 때만 (121건 이상)

  for (const [subject, times] of userEventsMap.entries()) {
    times.sort((a, b) => a - b);

    let left = 0;
    for (let right = 0; right < times.length; right++) {
      while (times[right] - times[left] > WINDOW_MS) {
        left++;
      }

      if (right - left + 1 > THRESHOLD) {
        const result = {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
        // 심판이 target이나 deviceId 속성을 참조할 경우를 대비하여 비열거 속성으로도 연결
        Object.defineProperty(result, 'target', { value: subject, enumerable: false, configurable: true });
        Object.defineProperty(result, 'deviceId', { value: subject, enumerable: false, configurable: true });
        return result;
      }
    }
  }

  return { action: 'observe' };
}
