-- 5단계: notes 테이블의 PUBLIC, anon, authenticated 직접 접근 권한 전면 회수
-- (브라우저나 외부 클라이언트의 원본 Supabase REST API 직접 호출 차단, Vercel 서버 함수의 service_role만 허용)

-- ==============================================================================
-- [1] 적용 전 권한 상태 점검 (현재 상태 확인)
-- ==============================================================================
-- 1-1) role_table_grants 확인 (현재 authenticated에 부여된 권한 확인)
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'notes'
  AND grantee IN ('anon', 'authenticated')
ORDER BY grantee, privilege_type;

-- 1-2) has_table_privilege 확인
SELECT
  r.role,
  p.privilege,
  has_table_privilege(r.role, 'notes', p.privilege) AS has_privilege
FROM (VALUES ('anon'), ('authenticated')) AS r(role)
CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege)
ORDER BY r.role, p.privilege;


-- ==============================================================================
-- [2] PUBLIC, anon, authenticated의 모든 직접 권한 전면 회수
-- ==============================================================================
-- notes 테이블에 대한 PUBLIC, anon, authenticated 역할의 모든 권한을 회수하여 직접 Data API 접근 차단
REVOKE ALL ON TABLE notes FROM PUBLIC, anon, authenticated;

-- RLS 활성화 상태 유지 및 기존 RLS 정책 정리 (테이블 권한 자체가 없으므로 거부됨)
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "notes_select_own" ON notes;
DROP POLICY IF EXISTS "notes_insert_own" ON notes;
DROP POLICY IF EXISTS "notes_update_own" ON notes;
DROP POLICY IF EXISTS "notes_delete_own" ON notes;


-- ==============================================================================
-- [3] 적용 후 권한 상태 점검 (모든 권한 회수 확인)
-- ==============================================================================
-- 3-1) role_table_grants 확인 (anon, authenticated 모두 0건이어야 함)
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'notes'
  AND grantee IN ('anon', 'authenticated')
ORDER BY grantee, privilege_type;

-- 3-2) has_table_privilege 확인 (anon, authenticated 모두 8개 항목 전부 false여야 함)
SELECT
  r.role,
  p.privilege,
  has_table_privilege(r.role, 'notes', p.privilege) AS has_privilege
FROM (VALUES ('anon'), ('authenticated')) AS r(role)
CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege)
ORDER BY r.role, p.privilege;
