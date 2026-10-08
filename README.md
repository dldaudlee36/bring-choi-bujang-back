# BYTE BACK 방어전 | 내 자료실

이 프로젝트는 SKT ALEPH 방어전 실습을 위한 가상 자료실 애플리케이션입니다.  
포함된 메모 기록은 모두 실습을 위한 가상 데이터이며, 실제 개인정보나 비밀값은 포함되지 않습니다.

---

## 📌 현재 단계: 5단계 (자료 요청을 서버 한곳으로 모읍니다) · 100점 만점 요건 완비

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

* **보너스 작전: 무차별 로그인 공격 탐지 (XDR)**:
  - `xdr/fixtures/brute-force.json`의 가상 Wazuh 경보(T1110)를 분석하는 `xdr/brute-force/decide.mjs` 및 `patterns.json`을 구현했습니다.
  - 동일 IP 대량 실패 및 다중 계정 암호 대입(스프레이) 공격은 즉시 차단(`block`, 10건), 소수 실패 및 모호한 시도는 주의 경보(`alert`, 9건), 정상 세션 활동은 기록(`record`, 9건)으로 분류합니다.

---

## 🔄 다시 실행하는 방법

1. **로컬 테스트 실행**:
   ```bash
   npm run test:r5
   ```
2. **보너스 작전(XDR) 경보 분석 실행**:
   ```bash
   npm run xdr:run -- brute-force
   ```
3. **제출 묶음 생성 및 자기 점검**:
   ```bash
   npm run bundle
   ```
4. **배포 사이트 확인**:
   - 배포 주소: https://choi-bujang-secret-vault-6asl.vercel.app
   - 로그인하지 않은 창에서는 자료가 노출되지 않습니다.
   - 사용자 A/B 각자 로그인 시 본인의 메모만 CRUD가 정상 수행됩니다.
   - 원본 Supabase API로 직접 요청 시 차단됩니다.

---

## ⚠️ 한계 및 남은 보안 약점

1. **동적 판정기(Decider) 미적용 (6단계 이후 과제)**:
   - 현재는 사용자 인증 및 소유자 대조 로직만 적용되어 있으며, 기기 등록 여부, 세션 신호, 다중 인증(MFA) 등을 종합 평가하는 동적 정책 판정기(`src/decider.mjs`)는 초기 차단 상태(`starter.deny`)로 유지되어 있습니다.
