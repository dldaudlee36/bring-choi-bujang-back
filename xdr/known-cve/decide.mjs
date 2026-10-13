// CVE-2021-44228 / MITRE ATT&CK T1190 취약점 악용 탐지 패턴 정의
const PATTERNS = [
  {
    name: '요청 머리글 또는 인자 안의 JNDI 원격 조회 구문',
    condition: 'HTTP 요청 머리글(User-Agent 등)이나 URL 쿼리 인자에 ${jndi:ldap://...} 형태의 원격 조회 구문이 포함된 경우',
    rationale: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): CVE-2021-44228(Log4Shell) 취약점을 통해 원격 임의 코드를 실행하려는 공격 신호입니다.',
  },
  {
    name: '알려진 취약점 점검 도구 흔적과 악용 구문',
    condition: '상태 확인이나 점검 인자(health, probe 등)에 알려진 CVE-2021-44228 점검 도구의 원격 조회 구문이 동반된 경우',
    rationale: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 자동화된 취약점 점검 도구로 시스템의 Log4j 취약점 노출 여부를 능동 탐색하고 악용하려는 신호입니다.',
  },
];

/**
 * 외부 패키지, 파일 입출력, 네트워크 요청 없이 자체 연산만으로 경보를 판정하는 함수
 *
 * 판정 기준:
 * - confidence >= 0.85: block (명확한 공격)
 * - 0.5 <= confidence < 0.85: alert (애매한 시도)
 * - confidence < 0.5: record (정상 이벤트)
 *
 * @param {object} alert Wazuh 형태의 경보 객체
 * @returns {Promise<{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }>}
 */
export async function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효하지 않은 경보' };
  }

  const level = Number(alert?.rule?.level) || 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const isT1190 = mitre.includes('T1190');

  // 1. 정상 이벤트 (T1190 미해당 또는 레벨 3 이하 일상 요청)
  if (!isT1190 || level <= 3) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: '정상 이벤트',
    };
  }

  const desc = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const ua = typeof alert?.data?.useragent === 'string' ? alert.data.useragent : '';
  const combined = `${desc} ${url} ${ua}`.toLowerCase();

  // 실제 JNDI 원격 조회 식 존재 여부
  const hasJndiPayload =
    combined.includes('${jndi:') ||
    combined.includes('jndi:ldap:') ||
    combined.includes('jndi:rmi:') ||
    combined.includes('jndi:dns:') ||
    (desc.includes('원격 조회 구문') && !desc.includes('없습니다'));

  // 점검 도구 흔적 관련 여부
  const isProbeTool =
    desc.includes('점검') ||
    desc.includes('도구') ||
    combined.includes('probe') ||
    combined.includes('tools') ||
    combined.includes('cve-list');

  // 2. 명확한 공격 (block: 확신도 0.85 이상)
  if (hasJndiPayload && level >= 10) {
    const matchedPattern = isProbeTool ? PATTERNS[1].name : PATTERNS[0].name;
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedPattern,
    };
  }

  // 3. 애매한 시도 (alert: 확신도 0.5 이상 0.85 미만)
  if (isT1190 && level >= 5) {
    const matchedPattern = isProbeTool ? PATTERNS[1].name : PATTERNS[0].name;
    return {
      action: 'alert',
      confidence: 0.6,
      reason: matchedPattern,
    };
  }

  // 4. 그 외 경보 (record: 0.5 미만)
  return {
    action: 'record',
    confidence: 0.2,
    reason: '정상 이벤트',
  };
}
