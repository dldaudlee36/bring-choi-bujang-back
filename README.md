# BYTE BACK 방어전 | 내 자료실

이 프로젝트는 SKT ALEPH 방어전 실습을 위한 가상 자료실 애플리케이션입니다.  
포함된 메모 기록은 모두 실습을 위한 가상 데이터이며, 실제 개인정보나 비밀값은 포함되지 않습니다.

---

## 📌 현재 단계: 6단계 (등록한 기기만 자료실에 들어옵니다) · 5단계 기능 유지

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

* **보너스 작전 2: 웹 주입 공격 탐지 및 ZTNA 거부 규칙 연동 (XDR)**:
  - `xdr/fixtures/web-injection.json`의 가상 Wazuh 경보(MITRE ATT&CK T1190)를 분석하는 `xdr/web-injection/decide.mjs` 및 `patterns.json`을 구현했습니다.
  - SQL 구문 삽입, 스크립트 태그 삽입, 상위 경로 이동(`../`) 등 명확한 공격은 차단(`block`, 8건), 단발성/수업명 등 애매한 시도는 경보(`alert`, 9건), 정상 활동은 기록(`record`, 9건)으로 판정합니다.
  - 차단 대상 IP는 ZTNA 판정기(`src/decider.mjs`)에 만료 시각과 근거 경보 번호가 포함된 거부 규칙으로 연동되어 우선 차단되며, 애매한 시도는 `xdr/alerts.log`에 누적 기록됩니다.

* **6단계: 등록한 기기만 자료실에 들어옵니다 (판정기 규칙 `device_registered`)**:
  - `src/decider.mjs`는 요청의 `deviceRegistered`가 `true`일 때만 `allow`(이유 코드 `approved`)를 돌려줍니다.
  - `false`이거나 값이 없으면 `deny`와 이유 코드 `device_not_registered`로 거부합니다. 규칙 이름은 `device_registered`입니다.
  - 이번 과정에는 따로 설치할 접속 프로그램이 없습니다. 기존 자료실 주소와 브라우저 화면은 그대로입니다.
  - 미등록 기기를 앞세운 실제 공격 시험은 심판이 맡습니다. 아래 `npm run decider:test`는 가상 요청 연습이며 심판 판정이 아닙니다.

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
   ```
3. **6단계 판정기 확인 (가상 요청 연습)**:
   ```bash
   npm run decider:test
   ```
   - 확인 순서: ① 위 명령을 저장소 루트에서 실행합니다. ② 「통과 · 등록 기기의 정상 요청」이 나오는지 봅니다(`allow`). ③ 「통과 · 미등록 기기의 가상 요청」이 나오는지 봅니다(`deny`, 이유 코드 `device_not_registered`).
   - 두 줄이 모두 「통과」이면 정상입니다. 「확인 필요」가 나오면 `src/decider.mjs`의 `device_registered` 규칙을 다시 봅니다.
   - 설치할 접속 프로그램은 없습니다. 이 명령은 심판 통과 증거가 아니며, 미등록 기기 공격은 심판이 시험합니다.
4. **제출 묶음 생성 및 자기 점검**:
   ```bash
   npm run bundle
   ```
4. **배포 사이트 확인**:
   - 배포 주소: https://rescue-choi-bujang-pc.vercel.app
   - 로그인하지 않은 창에서는 자료가 노출되지 않습니다.
   - 사용자 A/B 각자 로그인 시 본인의 메모만 CRUD가 정상 수행됩니다.
   - 원본 Supabase API로 직접 요청 시 차단됩니다.

---

## ⚠️ 한계 및 남은 보안 약점

1. **판정기는 기기 등록 규칙 하나만 구현 (7단계 이후 과제)**:
   - `src/decider.mjs`는 `device_registered` 규칙 하나만 구현했습니다. 세션 신호 조합, 추가 본인 확인(`step_up`) 등은 아직 없습니다.
