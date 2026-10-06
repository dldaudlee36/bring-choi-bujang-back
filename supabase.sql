-- 4단계: notes 테이블 최소 권한(GRANT/REVOKE) 및 RLS 정책

-- ==============================================================================
-- [1] 적용 전 권한 상태 점검 (SQL Editor에서 먼저 실행해 볼 수 있습니다)
-- ==============================================================================
-- 1-1) role_table_grants 점검
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'notes'
  AND grantee IN ('anon', 'authenticated')
ORDER BY grantee, privilege_type;

-- 1-2) has_table_privilege 점검
SELECT
  r.role,
  p.privilege,
  has_table_privilege(r.role, 'notes', p.privilege) AS has_privilege
FROM (VALUES ('anon'), ('authenticated')) AS r(role)
CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege)
ORDER BY r.role, p.privilege;


-- ==============================================================================
-- [2] 권한 회수 및 최소 권한 부여
-- ==============================================================================
-- PUBLIC, anon, authenticated의 모든 기존 권한 회수
REVOKE ALL ON TABLE notes FROM PUBLIC, anon, authenticated;

-- authenticated 역할에 대해서만 SELECT, INSERT, UPDATE, DELETE 권한 부여
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE notes TO authenticated;


-- ==============================================================================
-- [3] Row Level Security (RLS) 활성화 및 본인 행 한정 정책 설정
-- ==============================================================================
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- 기존 정책이 있다면 정리
DROP POLICY IF EXISTS "notes_select_own" ON notes;
DROP POLICY IF EXISTS "notes_insert_own" ON notes;
DROP POLICY IF EXISTS "notes_update_own" ON notes;
DROP POLICY IF EXISTS "notes_delete_own" ON notes;

-- SELECT 정책: auth.uid() = owner_id일 때만 조회 허용 (기존 행 USING)
CREATE POLICY "notes_select_own" ON notes
  FOR SELECT
  TO authenticated
  USING (auth.uid() = owner_id);

-- INSERT 정책: auth.uid() = owner_id일 때만 추가 허용 (새 행 WITH CHECK)
CREATE POLICY "notes_insert_own" ON notes
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = owner_id);

-- UPDATE 정책: auth.uid() = owner_id일 때만 수정 허용 (기존 행 USING + 새 행 WITH CHECK)
CREATE POLICY "notes_update_own" ON notes
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = owner_id)
  WITH CHECK (auth.uid() = owner_id);

-- DELETE 정책: auth.uid() = owner_id일 때만 삭제 허용 (기존 행 USING)
CREATE POLICY "notes_delete_own" ON notes
  FOR DELETE
  TO authenticated
  USING (auth.uid() = owner_id);


-- ==============================================================================
-- [4] 적용 후 권한 상태 점검 (적용 후 확인용)
-- ==============================================================================
-- 4-1) role_table_grants 확인
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'notes'
  AND grantee IN ('anon', 'authenticated')
ORDER BY grantee, privilege_type;

-- 4-2) has_table_privilege 확인
SELECT
  r.role,
  p.privilege,
  has_table_privilege(r.role, 'notes', p.privilege) AS has_privilege
FROM (VALUES ('anon'), ('authenticated')) AS r(role)
CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege)
ORDER BY r.role, p.privilege;
