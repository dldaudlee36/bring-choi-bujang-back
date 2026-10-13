# BYTE BACK 방어전 | 내 자료실

이 프로젝트는 SKT ALEPH 방어전 실습을 위한 가상 자료실 애플리케이션입니다.  
포함된 메모 기록은 모두 실습을 위한 가상 데이터이며, 실제 개인정보나 비밀값은 포함되지 않습니다.

---

## 📌 현재 단계: 8단계 (자료마다 갈 수 있는 구역을 나눕니다) · 이전 단계 기능 유지

### 1. 동작 방식 및 현재 작동하는 기능
* **자료 요청 단일 진입로 강제 (Vercel Serverless Gateway)**:
  - 브라우저 클라이언트의 모든 메모 읽기·추가·수정·삭제 요청은 오직 Vercel 서버 함수(`/api/notes`, `/api/notes/:id`)만을 통해 수행됩니다.
  - 로그인 요청 역시 서버 전용 함수(`/api/login`)를 통해서만 수행됩니다.
* **화면 코드 내 공개 키 전면 제거 (Bonus +10점)**:
  - 브라우저 코드(`public/index.html`)에서 Supabase SDK 및 `SUPABASE_ANON_KEY`를 완전히 제거하여 프론트엔드에 어떠한 키도 남기지 않았습니다.
  - 모든 키(`SUPABASE_SECRET_KEY`)는 오직 Vercel 서버 함수 내부 환경변수에서만 사용됩니다.
* **원본 DB 직접 접근 권한 전면 회수 (Bypass Attack Blocked)**:
  - Supabase `notes` 테이블에 대해 `PUBLIC`, `anon`, `authenticated` 역할의 모든 직접 권한을 회수(`REVOKE ALL`)했습니다.
  - 공격자가 `anon` 공개키나 탈취한 사용자 토큰을 이용해 원본 Supabase REST API(`https://<project>.supabase.co/rest/v1/notes`)로 직접 접근하더라도 `401/403 (permission denied)`로 원천 차단됩니다.
* **첫 화면 보안 헤더 적용 (Bonus +10점)**:
  - `vercel.json`의 `headers` 설정을 통해 모든 첫 화면 및 정적 응답에 `X-Content-Type-Options: nosniff` 보안 헤더가 전송됩니다.
* **설정 및 허용 경로 (`originalApiUrl`, `allowedRoutes`) (Bonus +10점)**:
  - 배포 식별 정보(`scripts/deployment-identity.mjs`)에 `originalApiUrl`을 연동하여 `public/aleph.json`에 HTTPS 원본 자료 주소가 정상 생성됩니다.
  - `aleph.config.json`의 `allowedRoutes`에 실제 사용되는 허용 경로들이 올바르게 등록되어 있습니다.

* **보너스 작전 1: 무차별 로그인 공격 탐지 (XDR)**:
  - `xdr/fixtures/brute-force.json`의 가상 Wazuh 경보(T1110)를 분석하는 `xdr/brute-force/decide.mjs` 및 `patterns.json`을 구현했습니다.
  - 동일 IP 대량 실패 및 다중 계정 암호 대입(스프레이) 공격은 즉시 차단(`block`, 10건), 소수 실패 및 모호한 시도는 주의 경보(`alert`, 9건), 정상 세션 활동은 기록(`record`, 9건)으로 분류합니다.

* **보너스 작전 2: 웹 주입 공격 탐지 및 거부 규칙 연동 (XDR)**:
  - `xdr/fixtures/web-injection.json`의 가상 Wazuh 경보(MITRE ATT&CK T1190)를 분석하는 `xdr/web-injection/decide.mjs` 및 `patterns.json`을 구현했습니다.
  - SQL 구문 삽입, 스크립트 태그 삽입, 상위 경로 이동(`../`) 등 명확한 공격은 차단(`block`, 8건), 단발성/수업명 등 애매한 시도는 경보(`alert`, 9건), 정상 활동은 기록(`record`, 9건)으로 판정합니다.
  - 차단 대상 IP는 판정기(`src/decider.mjs`)에 만료 시각과 근거 경보 번호가 포함된 거부 규칙으로 연동되어 우선 차단되며, 애매한 시도는 `xdr/alerts.log`에 누적 기록됩니다.

* **보너스 작전 3: 알려진 취약점(Log4Shell, CVE-2021-44228) 악용 탐지 및 거부 규칙 연동 (XDR)**:
  - `xdr/fixtures/known-cve.json`의 가상 Wazuh 경보(MITRE ATT&CK T1190)를 분석하는 `xdr/known-cve/decide.mjs`, `patterns.json`, `respond.mjs` 및 `read-alerts.mjs`를 구현했습니다.
  - 요청 머리글이나 주소 인자에 JNDI 원격 조회 식(`${jndi:ldap://...}`)이 포함된 명확한 취약점 공격은 차단(`block`, 8건), 단순 명칭 검색 및 점검 흔적은 경보(`alert`, 8건), 정상 활동은 기록(`record`, 8건)으로 판정합니다.
  - 차단 대상 8개 공격 IP는 만료 시각(`2026-10-18T00:00:00.000Z`)과 경보 ID가 포함된 거부 규칙(`xdr/deny-rules.json`)에 연동되며, 알림 시도는 `xdr/alerts.log`에 누적 기록됩니다. 정상 사용자는 거부 규칙에 등록되지 않습니다.

* **6·7단계: 등록 기기 통제 및 이상 접속 재인증 (`device_registered`, `step_up_required`)**:
  - `src/decider.mjs`는 로그인 주체(`subjectId`), 기기 ID(`deviceId`), 등록 상태(`deviceRegistered === true`), 읽기 동작(`method === 'GET'`), 자료실 경로(`service === 'notes'`)를 모두 만족할 때만 정상 요청을 허용합니다. 미등록 기기는 `deny` (`device_not_registered`)로 거부합니다.
  - 평소와 다른 심야 시각 + 낯선 네트워크 + 대량 조회의 복합 이상 사건 발생 시 지역(`region: 'foreign'`) 하나만으로 영구 차단하지 않고 추가 인증(`step_up`, 이유 코드 `step_up_required`)으로 안내합니다.
  - 추가 인증을 완료한 재인증 요청(`stepUp.verified === true`, 유효시간 0~900초)은 정상 허용(`allow`, 이유 코드 `approved`)합니다.
  - 제공 엔진의 재로그인 시각 검증 계약 미제공으로 실제 서버리스 배포 단의 재로그인 차단은 미실행으로 보존하고 가상 사건으로 안전하게 연습합니다.

* **8단계: 구역 접근 제어 및 소유자·강사 권한 대조 (`zone_access`)**:
  - 내 자료실 메모(`note-${id}`)와 강사 공지(`notice-instructor-01`)를 서로 다른 구역 자원 ID로 구별하고 화면 배지로 표시합니다.
  - 판정기(`src/decider.mjs`)에 `zone_access` 규칙을 구현하여, 자기 메모 읽기·수정은 허용하고, 타인 메모 접근(`cross_user_forbidden`), 강사 공지 수정(`notice_update_forbidden`), `:id` 깊이의 기능 경로(`export` 등, `unknown_route`) 및 알 수 없는 경로는 거부합니다.
  - 자료 API(`api/notes.js`)에서도 화면 메뉴나 요청 본문·쿼리의 `role`을 신뢰하지 않고, 암호학적으로 검증된 토큰 사용자와 저장된 소유자·강사 권한을 재대조하여 짧은 사유(`NOT_OWNER`, `INSUFFICIENT_ROLE`)로 차단합니다.

---

## 🔄 다시 실행하는 방법

1. **로컬 테스트 실행**:
   ```bash
   npm run test:r5
   ```
2. **보너스 작전(XDR) 경보 분석 실행**:
   ```bash
   # 무차별 로그인 공격 분석
   npm run xdr:run -- brute-force

   # 웹 주입 공격 분석
   npm run xdr:run -- web-injection

   # 알려진 취약점(CVE-2021-44228) 악용 분석 및 대응 연동
   npm run xdr:run -- known-cve
   node xdr/known-cve/respond.mjs
   ```
3. **7단계 판정기 및 복합 이상 사건 확인 (가상 요청 연습)**:
   ```bash
   # 가상 사건 2건 집중 대조
   npm run fixture:7

   # 판정기 전체 규칙(기기 등록 + 복합 이상 + 재인증 통과) 연습
   npm run decider:test
   ```
   - 확인 순서: ① 위 명령을 저장소 루트에서 실행합니다. ② 「통과 · 등록 기기의 정상 요청」, 「통과 · 미등록 기기의 가상 요청」, 「통과 · 복합 이상 접속」, 「통과 · 다시 확인한 복합 이상 접속」 4개 항목이 모두 나오는지 확인합니다.
4. **제출 묶음 생성 및 자기 점검**:
   ```bash
   npm run bundle
   ```
5. **배포 사이트 확인**:
   - 배포 주소: https://rescue-choi-bujang-pc.vercel.app
   - 로그인하지 않은 창에서는 자료가 노출되지 않습니다.
   - 사용자 A/B 각자 로그인 시 본인의 메모만 CRUD가 정상 수행됩니다.
   - 원본 Supabase API로 직접 요청 시 차단됩니다.

---

## ⚠️ 한계 및 남은 보안 약점

1. **실시간 사건 탐지 및 동적 차단 (9단계 이후 과제)**:
   - 현재는 판정기 규칙(`device_registered`, `step_up_required`, `zone_access`) 및 API 소유자 대조가 정적으로 동작하며, 운영 반 엔진의 사건 전달·접속 회수 연동(`src/detect.mjs`)은 다음 단계 과제입니다.
