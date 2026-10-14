# BYTE BACK 방어전 | 내 자료실

이 프로젝트는 SKT ALEPH 방어전 실습을 위한 가상 자료실 애플리케이션입니다.  
포함된 메모 기록은 모두 실습을 위한 가상 데이터이며, 실제 개인정보나 비밀값은 포함되지 않습니다.

---

## 10단계 복구 확인 결과 (사본 일치 · 복구 뒤 재시험)

확인 기준 커밋: `e0435f3`. 아래 명령은 이 커밋에서 실제로 실행한 결과이며, 실행하지 않은 시험은 미실행으로 적었습니다.

### 사본 일치를 어떻게 확인하나

- 사본: 메모가 처음 만들어질 때 DB 트리거(`capture_note_original`)가 `note_restore_backups`에 제목·본문·내용 지문을 한 번만 남깁니다. 이후 수정(PUT)은 사본을 바꾸지 않습니다. 트리거 설치 전에 있던 메모는 `db/baseline-seed-existing-notes.sql`로 한 번 사본을 채웠고, 출처를 `baseline_verified`로 구분합니다. 사본 표는 서버(service_role)도 읽기만 가능하고 수정·삭제 권한이 없습니다.
- 지문: `sha256(UTF-8 "제목바이트수:" + 제목 + 본문)`. 서버(`src/restore-api.mjs`의 `noteHash`)와 DB 함수(`restore_verified_note`)가 같은 방식으로 계산합니다.
- 복구(`POST /api/restore/:noteId`, 같은 처리기가 `POST /api/notes/:id/restore`도 받음) 때 서버가 본인 소유 사본을 직접 읽고 지문과 정책 지문을 다시 계산해 저장값과 같을 때만 복원합니다. 복원한 메모는 다시 읽어 ID·소유자·내용 지문이 사본과 같은지 한 번 더 대조하고, 다르면 409(`backup_unverified` / `restore_mismatch`)로 멈춥니다. 응답의 `contentSha256`이 사본 지문입니다.
- 요청 본문과 쿼리의 내용·소유자 값은 읽지 않습니다. 쿼리의 `noteId`는 경로의 ID와 같은지만 확인합니다. 그래서 복구 내용을 요청으로 끼워 넣을 수 없습니다.

### 복구 뒤 1~9단계 다시 확인한 결과

| 순서 | 확인 | 정상(허용되어야 함) | 금지(거부되어야 함) | 실행 여부 · 실제 결과 |
|---|---|---|---|---|
| 1 | 10단계 사본 일치 | 변조 메모 복구 200·`reverted`, 삭제 메모 200·`recreated`, `contentSha256` = 원본 지문 | 사본 없음 404, 남의 사본 404, 사본 지문 불일치 409, 비인증 401, 복구 뒤 재대조 불일치 409 | `npm run test:r10` 실행 · pass 8 / fail 0 (가짜 토큰·메모리 DB 사용, 심판 판정 아님) |
| 2 | 1~5단계 공개 자료·로그인·원본 API | 로그인 사용자의 자기 메모 CRUD | `/data.json` 메모 없음, 토큰 없는 `/api/notes` 401, 원본 API 직접 접근 거부 | `npm run test:r5` 실행 · pass 2 / fail 0 |
| 3 | 6~7단계 기기·이상 접속 | 등록 기기 정상 요청 `allow` | 미등록 기기 `deny`, 복합 이상 `step_up` | `npm run decider:test` 4건 통과, `npm run fixture:7` 정상 `allow`·복합 이상 `step_up` |
| 4 | 8단계 구역 | 본인 메모 `allow` | 남의 메모·공지 수정·기능 경로 `deny` | `npm run decider:test` 실행 · 통과 |
| 5 | 9단계 탐지 | 120건 이하 `observe` | 10분 121건 이상 `propose_revocation` | `npm run detect:test` 6건 통과 |
| 6 | 배포된 복구 경로 (비인증) | 없음 | 토큰 없는 `POST /api/restore/:noteId`와 `POST /api/notes/:id/restore`는 401 `login_required`, GET은 405 | 배포 주소에 직접 요청해 확인 (커밋 `e0435f3` 배포 후) |
| 7 | 배포된 복구 경로 (시험 계정 B로 실제 변조→복구) | 200, 지문 일치 | 없음 | 미실행: 시험 계정 B 토큰이 없어 직접 보내지 않았습니다. 이 항목은 위 1번의 단위 시험으로만 확인했습니다. |

---

## 📌 현재 단계: 10단계 (백업에서 자료실을 되살립니다) · 이전 단계 기능 유지

### 1. 동작 방식 및 현재 작동하는 기능
* **자료 요청 단일 진입로 강제 (Vercel Serverless Gateway)**:
  - 브라우저 클라이언트의 모든 메모 읽기·추가·수정·삭제 요청은 오직 Vercel 서버 함수(`/api/notes`, `/api/notes/:id`)만을 통해 수행됩니다.
  - 로그인 요청 역시 서버 전용 함수(`/api/login`)를 통해서만 수행됩니다.
* **화면 코드 내 공개 키 전면 제거**:
  - 브라우저 코드(`public/index.html`)에서 Supabase SDK 및 `SUPABASE_ANON_KEY`를 완전히 제거하여 프론트엔드에 어떠한 키도 남기지 않았습니다.
  - 모든 키(`SUPABASE_SECRET_KEY`)는 오직 Vercel 서버 함수 내부 환경변수에서만 사용됩니다.
* **원본 DB 직접 접근 권한 전면 회수 (Bypass Attack Blocked)**:
  - Supabase `notes` 테이블에 대해 `PUBLIC`, `anon`, `authenticated` 역할의 모든 직접 권한을 회수(`REVOKE ALL`)했습니다.
  - 공격자가 `anon` 공개키나 탈취한 사용자 토큰을 이용해 원본 Supabase REST API(`https://<project>.supabase.co/rest/v1/notes`)로 직접 접근하더라도 `401/403 (permission denied)`로 원천 차단됩니다.
* **첫 화면 보안 헤더 적용**:
  - `vercel.json`의 `headers` 설정을 통해 모든 첫 화면 및 정적 응답에 `X-Content-Type-Options: nosniff` 보안 헤더가 전송됩니다.
* **설정 및 허용 경로 (`originalApiUrl`, `allowedRoutes`, `restoreRoute`)**:
  - 배포 식별 정보(`scripts/deployment-identity.mjs`)에 `originalApiUrl`과 `restoreRoute`를 연동하여 `public/aleph.json`에 HTTPS 원본 자료 주소 및 복구 엔드포인트가 정상 배포됩니다.
  - `aleph.config.json`의 `allowedRoutes`에 실제 사용되는 허용 경로들이 올바르게 등록되어 있습니다.
* **6·7단계: 등록 기기 통제 및 이상 접속 재인증 (`device_registered`, `step_up_required`)**:
  - `src/decider.mjs`는 로그인 주체(`subjectId`), 기기 ID(`deviceId`), 등록 상태(`deviceRegistered === true`), 읽기 동작(`method === 'GET'`), 자료실 경로(`service === 'notes'`)를 모두 만족할 때만 정상 요청을 허용합니다. 미등록 기기는 `deny` (`device_not_registered`)로 거부합니다.
  - 평소와 다른 심야 시각 + 낯선 네트워크 + 대량 조회의 복합 이상 사건 발생 시 지역(`region: 'foreign'`) 하나만으로 영구 차단하지 않고 추가 인증(`step_up`, 이유 코드 `step_up_required`)으로 안내합니다.
  - 추가 인증을 완료한 재인증 요청(`stepUp.verified === true`, 유효시간 0~900초)은 정상 허용(`allow`, 이유 코드 `approved`)합니다.
* **8단계: 구역 접근 제어 및 소유자·강사 권한 대조 (`zone_access`)**:
  - 내 자료실 메모와 강사 공지를 서로 다른 구역 자원 ID로 구별합니다.
  - 판정기(`src/decider.mjs`)에 `zone_access` 규칙을 구현하여, 자기 메모 읽기·수정은 허용하고, 타인 메모 접근, 강사 공지 수정(`notice_update_forbidden`), `:id` 깊이의 기능 경로(`/api/notes/export` 등) 및 알 수 없는 경로는 거부합니다.
  - 자료 API(`api/notes.js`)에서도 화면 메뉴나 요청 본문·쿼리의 `role`을 신뢰하지 않고, 암호학적으로 검증된 토큰 사용자와 저장된 소유자·강사 권한을 재대조하여 짧은 사유(`NOT_OWNER`, `INSUFFICIENT_ROLE`)로 차단합니다.
* **9단계: 도플갱어 탐지 및 권한 회수 제안 (`propose_revocation`)**:
  - 낯선 네트워크(`network === 'unusual'`)와 갑작스러운 다량 조회(`hasHighActivity`)가 동시에 나타날 때만 복합 의심 사건으로 판정하여 회수 제안(`propose_revocation`)을 반환합니다.
* **10단계: 검증된 사본 기반 단건 메모 복구 (`POST /api/notes/:id/restore`, `src/trial-policy-restore.mjs`)**:
  - **복구 엔드포인트**: `POST /api/restore/:noteId`. 설정의 `restoreRoute`에는 메서드를 제외한 `/api/restore/:noteId`만 기록합니다. 같은 처리기가 기존 `POST /api/notes/:id/restore`도 받습니다.
  - `src/trial-policy-restore.mjs`: `previewPolicyRestore`를 통해 사본 버전과 변경 범위(`service: notes`)를 사전 확인하고, `confirmationHash` 대조 시에만 `applyTrialPolicyRestore`로 가상 정책을 복원하며 다른 서비스 규칙과 감사 이력은 온전히 보존합니다.
  - `src/restore-api.mjs`: 심판 B 인증을 요구합니다. 요청 본문과 경로 밖의 쿼리는 읽지 않고 무시하며, 경로의 ID 한 건만 복원합니다. 처리 순서는 (1) 본인 소유 사본을 직접 읽기, (2) 사본의 내용 지문(`sha256('제목바이트수:제목본문')`)과 정책 지문을 다시 계산해 대조, (3) 현재 메모의 소유자 확인, (4) 복원, (5) 복원한 메모를 다시 읽어 ID·소유자·내용 지문을 사본과 대조입니다. 사본이 없으면 404, 사본 검증이 어긋나면 409(`backup_unverified`), 복원 결과가 어긋나면 409(`restore_mismatch`)입니다.
  - Supabase `restore_verified_note`: 같은 검증을 DB 안에서 한 번 더 수행하고, 잠금 안에서 복원과 감사 로그(`note_restore_audit`) 적재를 처리합니다. 메모를 만들 때는 DB 트리거가 사본을 자동으로 남기고, 이미 있던 메모는 `db/baseline-seed-existing-notes.sql`로 사본을 채웁니다.

---

## 🔄 복구 뒤 1~9단계 정상·금지 요청 재실행 순서

침해 사고(자료 변조·삭제) 발생 후, 복구를 실행하고 1~9단계의 정상·금지 요청이 올바르게 동작하는지 아래 순서대로 확인합니다.  
*(실행하지 않은 시험은 미실행으로 기록하며 결과를 임의로 꾸미지 않습니다.)*

### 1단계: 시험 정책 사본 검증 및 복구 API 단위 시험
* **실행 명령**:
  ```bash
  npm run test:r10
  ```
* **정상 결과 (복원 확인)**:
  - 시험 정책 사본 사전 검증, 변경 범위 확인 및 감사 보존 복구 테스트 통과.
  - 계정 B의 단건 복구 요청 및 불일치 사본 거부 단위 검증 통과.
* **거부 결과**: 사본에 없는 메모 요청은 404, 내용 해시 불일치 요청은 409, 비인증 요청은 401로 거부됩니다.

### 2단계: 1~5단계 기본 접근 통제 및 게이트웨이 재검증
* **실행 명령**:
  ```bash
  npm run test:r5
  ```
* **정상 결과**: Vercel 게이트웨이를 통한 로그인 사용자의 정상 메모 CRUD 요청은 정상 처리됩니다.
* **거부 결과 (금지 요청)**:
  - 비로그인 `/data.json` 요청 시 가상 메모가 노출되지 않습니다.
  - 비로그인 `/api/notes`, `/api/notes/:id` 요청 시 HTTP 401로 즉시 차단됩니다.
  - 원본 Supabase REST API(`.../rest/v1/notes`) 직접 접근 시 HTTP 401(또는 403)로 차단됩니다.

### 3단계: 6~7단계 기기 등록 및 이상 접속 재인증 재검증
* **실행 명령**:
  ```bash
  npm run fixture:7
  npm run decider:test
  ```
* **정상 결과**: 등록된 정상 기기의 정상 접속은 `allow` (`approved`)로 판정됩니다.
* **거부 결과 (금지 요청)**:
  - 미등록 기기의 접속은 판정기에서 `deny` (`device_not_registered`)로 거부됩니다.
  - 낯선 네트워크 + 심야 시간 등의 복합 이상 접속은 추가 인증 요구(`step_up`, `step_up_required`)로 차단·안내됩니다.
* ⚠️ **미실행 시험**: 제공 엔진의 실시간 재로그인 시각 검증 계약 미제공으로 실제 서버리스 배포 단의 재로그인 차단 점검은 **미실행**으로 보존합니다.

### 4단계: 8단계 구역 접근 제어 및 소유자 대조 재검증
* **실행 명령**:
  ```bash
  npm run decider:test
  ```
* **정상 결과**: 사용자 A의 본인 메모 요청은 `allow` (`approved`)를 유지합니다.
* **거부 결과 (금지 요청)**:
  - 사용자 B가 A의 메모에 접근 시 판정기에서 `deny` (`zone_access_denied`)로 엄격히 거부됩니다.
  - 강사 공지 자원에 대한 수정(PUT) 요청은 학생 권한 차단으로 거부됩니다.
  - `:id` 깊이의 기능 경로(`/api/notes/export`) 접근은 비인가 경로로 거부됩니다.

### 5단계: 9단계 도플갱어 폭주 조회 탐지 재검증
* **실행 명령**:
  ```bash
  npm run detect:test
  ```
* **정상 결과**: 10분 내 120건 이하의 정상 조회 및 분산 조회는 `{ action: 'observe' }`로 정상 기기 권한을 온전히 유지합니다.
* **거부/제안 결과 (이상 탐지)**:
  - 동일 신원의 10분 내 121건 이상 폭주 조회 발생 시 `{ action: 'propose_revocation', reasonCode: 'burst_read' }` 회수 제안을 반환합니다.
* ⚠️ **미실행 시험**: 운영 반 엔진의 실제 사건 스트림 실시간 전달 및 회수 집행 연동은 심판 가상 평가에 위임되므로 로컬 환경에서는 **미실행**으로 보존합니다.

### 6단계: 종합 점검 및 제출 묶음 확인
* **실행 명령**:
  ```bash
  npm run bundle
  ```
* **확인 사항**: 1~11단계 자기 점검이 모두 통과하고, `artifacts/submission.json` 제출 묶음이 정상 생성되는지 확인합니다.

---

## 11단계: 접속 앱과 기기 승인 화면

- `public/manifest.json`, 앱 아이콘, 오프라인 전용 안내와 service worker를 추가했습니다. 캐시는 공개 오프라인 안내만 저장하고 메모·API 응답·로그인 화면은 저장하지 않습니다. 설치는 기기 승인을 의미하지 않습니다.
- 로그인 토큰은 현재 페이지의 메모리에만 두며 이전 `byte-back-session` 저장값은 제거합니다. 새로고침하면 다시 로그인합니다. 개인키를 생성하거나 저장하지 않습니다.
- 승인 요청 버튼은 `POST /api/device/request`, 상태 확인은 `GET /api/device/status`를 호출합니다. 화면은 HTTP 200의 `approved === true`만 승인으로 사용합니다. 버튼 클릭·로그인·설치·요청 접수는 승인 근거가 아닙니다.
- 승인 전·오프라인·로그아웃에서는 메모 제목·본문·편집 화면을 지우고 보호 API를 요청하지 않습니다. 늦게 도착한 승인 응답도 로그아웃 뒤 화면을 열 수 없습니다.
- **실제 승인 연결의 정확한 차단점:** 이 저장소와 단계 안내에는 제공 엔진의 등록 요청 API, 서버가 검증할 기기 세션/서명 계약이 없습니다. 상태 API는 승인 전 `approved:false`, 요청 API는 `501`·`accepted:false`·`device_approval_contract_unavailable`을 반환합니다. 접수·승인을 완료했다고 기록하지 않습니다. 가짜 헤더로 승격하거나 별도의 기기 인증 체계를 만들어 엔진 규칙을 대체하지 않습니다.
- 제공 엔진의 요청 서명 확인은 학생 화면의 책임으로 옮기지 않았습니다. 기존 자료 API의 로그인·소유자·강사 권한 검사와 판정기를 유지했습니다. 운영 서명 없는 요청·경로/본문 변경의 실제 엔진 시험은 미실행입니다.
- 관련 로컬 시험 통과: `node --test test/device-approval.test.mjs`, `npm run test:r10`, `npm run decider:test`, `npm run detect:test`, `npm run build -- --local`. 승인된 서버 응답을 넣은 화면 단위시험은 실제 기기 승인 실측이 아닙니다.

---

## ⚠️ 한계 및 남은 보안 약점

1. **실시간 사건 탐지 및 동적 차단 집행**:
   - 현재 판정기 규칙(`device_registered`, `step_up_required`, `zone_access`) 및 탐지(`detect`)는 가상 사건으로 연습하며, 운영 반 엔진의 실제 사건 스트림 전달과 실시간 회수 집행은 심판의 가상 평가 및 운영 릴레이로 집행됩니다.
