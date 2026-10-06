-- 4단계 학습용 SQL: A 계정과 B 계정의 소유자 ID(owner_id) 연결

-- 1. 기존 가상 메모 세 건('과제', '포트폴리오', '아침 리추얼')에 A의 owner_id 연결
UPDATE notes
SET owner_id = (SELECT id FROM auth.users WHERE email = 'A_이메일' LIMIT 1)
WHERE id IN (
  'a0000000-0000-0000-0000-000000000001',
  'a0000000-0000-0000-0000-000000000002',
  'a0000000-0000-0000-0000-000000000003'
);

-- 2. B 소유의 공개 가능한 시험 메모 한 건('훈련 행정 자료') 준비
INSERT INTO notes (id, title, body, owner_id)
VALUES (
  'a0000000-0000-0000-0000-000000000004',
  '훈련 행정 자료',
  '실습용 가상 행정 기록',
  (SELECT id FROM auth.users WHERE email = 'B_이메일' LIMIT 1)
)
ON CONFLICT (id) DO UPDATE
SET owner_id = (SELECT id FROM auth.users WHERE email = 'B_이메일' LIMIT 1);

-- 3. 확인용 쿼리: A의 세 메모와 B의 한 메모에 각각 올바른 owner_id가 설정되었는지 확인
SELECT id, title, owner_id FROM notes ORDER BY id;
