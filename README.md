# BYTE BACK 방어전 | 내 자료실

이 프로젝트는 SKT ALEPH 방어전 실습을 위한 가상 자료실 애플리케이션입니다.  
포함된 메모 기록은 모두 실습을 위한 가상 데이터이며, 실제 개인정보나 비밀값은 포함되지 않습니다.

---

## 📌 현재 단계: 5단계 (자료 요청을 서버 한곳으로 모읍니다)

### 1. 동작 방식 및 현재 작동하는 기능
* **자료 요청 단일 진입로 강제 (Vercel Serverless Gateway)**:
  - 브라우저 클라이언트의 모든 메모 읽기·추가·수정·삭제 요청은 오직 Vercel 서버 함수(`/api/notes`, `/api/notes/:id`)만을 통해 수행됩니다.
  - 브라우저 코드 내에는 원본 DB를 직접 조작하는 API 호출이 일체 존재하지 않습니다.
* **원본 DB 직접 접근 권한 전면 회수 (Bypass Attack Blocked)**:
  - Supabase `notes` 테이블에 대해 `PUBLIC`, `anon`, `authenticated` 역할의 모든 직접 권한을 회수(`REVOKE ALL`)했습니다.
  - 공격자가 `anon` 공개키나 탈취한 사용자 토큰을 이용해 원본 Supabase REST API(`https://<project>.supabase.co/rest/v1/notes`)로 직접 접근하여 자료를 조회하거나 수정·삭제하려는 시도는 모두 `401/403 (permission denied)`로 원천 차단됩니다.
* **서버 전용 키(`service_role`) 기반 보안 중계**:
  - 오직 서버 측 환경변수에만 존재하는 `SUPABASE_SECRET_KEY`를 통해 Supabase에 접근하므로, 브라우저에는 서버 전용 키가 노출되지 않으며 서버 함수의 토큰 검증 및 소유자 검증 로직을 우회할 수 없습니다.
* **설정 및 허용 경로 (`originalApiUrl`, `allowedRoutes`)**:
  - `aleph.config.json`에 원본 자료 HTTPS 주소(`https://mxiycelcxviyvsixuytr.supabase.co/rest/v1/notes`)를 `originalApiUrl`로 등록했습니다.
  - `allowedRoutes`에 실제 사용되는 5개 엔드포인트(`GET /api/notes`, `POST /api/notes`, `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`)를 유지합니다.

---

## 🔄 다시 실행하는 방법

1. **로컬 테스트 실행**:
   ```bash
   npm run test:r5
   ```
2. **제출 묶음 생성 및 자기 점검**:
   ```bash
   npm run bundle
   ```
3. **배포 사이트 확인**:
   - 배포 주소: https://choi-bujang-secret-vault-6asl.vercel.app
   - 로그인하지 않은 창에서는 자료가 노출되지 않습니다.
   - 사용자 A/B 각자 로그인 시 본인의 메모만 CRUD가 정상 수행됩니다.
   - 원본 Supabase API로 직접 요청 시 차단됩니다.

---

## ⚠️ 한계 및 남은 보안 약점

1. **동적 판정기(Decider) 미적용 (6단계 이후 과제)**:
   - 현재는 사용자 인증 및 소유자 대조 로직만 적용되어 있으며, 기기 등록 여부, 세션 신호, 다중 인증(MFA) 등을 종합 평가하는 동적 정책 판정기(`src/decider.mjs`)는 초기 차단 상태(`starter.deny`)로 유지되어 있습니다.
