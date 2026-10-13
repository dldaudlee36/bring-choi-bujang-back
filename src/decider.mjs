// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계 규칙 device_registered: 등록되어 사용자와 묶인 기기만 내 자료실 읽기(GET notes)를 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  // 엔진이 확인해 넘긴 로그인(subjectId)·기기(deviceId, deviceRegistered)·동작(method)·경로(service)만 검증합니다.
  const hasLogin = typeof request?.subjectId === 'string' && request.subjectId.trim().length > 0;
  const hasDevice = typeof request?.deviceId === 'string' && request.deviceId.trim().length > 0;
  const isDeviceRegistered = request?.deviceRegistered === true;
  const isReadAction = request?.method === 'GET';
  const isNotesService = request?.service === 'notes';

  if (hasLogin && hasDevice && isDeviceRegistered && isReadAction && isNotesService) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'deny',
    reasonCode: 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
