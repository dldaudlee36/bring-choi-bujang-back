# BYTE BACK 방어전 | 내 자료실

이 프로젝트는 SKT ALEPH 방어전 실습을 위한 가상 자료실 애플리케이션입니다.  
포함된 메모 기록은 모두 실습을 위한 가상 데이터이며, 실제 개인정보나 비밀값은 포함되지 않습니다.

---

## 📌 현재 단계: 4단계 (로그인해도 내 자료만 보이게 합니다)

### 1. 동작 방식 및 현재 작동하는 기능
* **사용자 인증 (Identity Provider)**: Supabase Auth 공식 SDK를 연동하여 이메일·비밀번호 기반 로그인/로그아웃 및 브라우저 세션 관리를 수행합니다.
* **API 토큰 검문소 연동**: 자료 API(`/api/notes`, `/api/notes/:id`)에 `src/verify-login.mjs` 검증기를 적용하여, 유효한 Bearer 토큰이 없는 요청은 즉시 `401 Unauthorized`로 차단합니다.
* **객체 수준 소유권 인가 (Object-Level Ownership Authorization)**:
  - `GET /api/notes`: 로그인한 본인의 `owner_id`와 일치하는 메모 목록만 반환합니다.
  - `GET /api/notes/:id`: 타인 소유의 메모 요청 시 `403 Forbidden`으로 거부합니다.
  - `POST /api/notes`: 외부 입력(URL/본문)의 `owner_id`를 배제하고 검증된 토큰의 사용자 ID로 저장합니다.
  - `PUT /api/notes/:id`: 기존 행 소유자 확인 및 소유자 변경 시도를 차단(`403 Forbidden`)하며 본인의 메모만 수정을 허용합니다.
  - `DELETE /api/notes/:id`: 본인 소유의 메모만 삭제를 허용하고 타인 메모 삭제 시도는 `403 Forbidden`으로 차단합니다.
* **데이터베이스 행 수준 보안 (RLS & Least Privilege)**:
  - `notes` 테이블에 대해 `anon` 역할의 모든 권한을 회수(`REVOKE ALL`)했습니다.
  - `authenticated` 역할에만 필요한 최소 권한(`SELECT`, `INSERT`, `UPDATE`, `DELETE`)을 부여했습니다.
  - `auth.uid() = owner_id` 조건의 RLS 정책을 적용하여 DB 레벨에서도 타인 행 접근 및 변조를 원천 차단했습니다.
* **허용 경로 등록 (`allowedRoutes`)**:
  - `aleph.config.json`의 `allowedRoutes`에 실제 사용되는 5개 메서드 및 경로(`GET /api/notes`, `POST /api/notes`, `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`)를 명시했습니다.

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
   - 로그인하지 않은 시크릿 창에서는 자료 및 작성 폼이 숨겨집니다.
   - 사용자 A로 로그인 시 A의 메모 3건만 보이고 수정/삭제가 가능합니다.
   - 사용자 B로 로그인 시 B의 메모 1건만 보이고 수정/삭제 및 신규 생성이 가능합니다.
   - A와 B 간에 서로의 메모가 노출되거나 침범되지 않습니다.

---

## ⚠️ 한계 및 남은 보안 약점

1. **원본 API 연동 및 게이트웨이 검증 부재 (5단계 이후 과제)**:
   - 현재는 직접 구현된 서버리스 함수를 통해 DB에 접근하고 있으나, 원본 API 게이트웨이 및 역방향 프록시 연동 단계의 검증은 아직 적용되지 않았습니다.
2. **반사 공격 및 신호 기반 동적 정책 판정 부재 (6단계 이후 과제)**:
   - 정적 소유권 검증 외에 실시간 세션/기기 신호에 기반한 동적 위험 판정기(`src/decider.mjs`) 규칙은 초기 상태(`starter.deny`)로 유지되어 있습니다.
