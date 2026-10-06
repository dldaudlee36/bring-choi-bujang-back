-- 3단계 notes 테이블 스키마 (id UUID, title, body, owner_id)
DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  body text NOT NULL,
  owner_id uuid,
  created_at timestamptz DEFAULT now()
);

-- Row Level Security(RLS) 활성화 및 anon/authenticated 직접 조회 권한 회수 (서버리스 함수 service_role을 통해서만 접근)
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE notes FROM anon, authenticated;

-- 실습용 가상 메모 네 건 초기 삽입 (고유 UUID 부여)
INSERT INTO notes (id, title, body)
VALUES
  ('a0000000-0000-0000-0000-000000000001', '과제', '실습용 가상 과제 기록'),
  ('a0000000-0000-0000-0000-000000000002', '포트폴리오', '실습용 가상 포트폴리오 기록'),
  ('a0000000-0000-0000-0000-000000000003', '아침 리추얼', '실습용 가상 리추얼 기록'),
  ('a0000000-0000-0000-0000-000000000004', '훈련 행정 자료', '실습용 가상 행정 기록');
