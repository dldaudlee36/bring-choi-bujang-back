-- 일회성: 트리거 설치 전에 만들어진 계정 B의 TEST_MEMO 한 건만 기준 사본으로 등록한다.
-- 제목과 본문이 작성 당시 원본과 정확히 일치할 때만 등록되며, 다르면 아무 행도 만들지 않는다.
-- 다른 메모는 절대 복사하지 않는다. 출처는 'baseline_verified'로 구분해 기록한다.
insert into public.note_restore_backups(note_id, owner_id, title, content, created_at, content_sha256, policy_sha256, provenance)
select n.id, n.owner_id, n.title, coalesce(n.content, n.body, ''), coalesce(n.created_at, now()),
  encode(extensions.digest(convert_to(octet_length(convert_to(n.title, 'UTF8'))::text || ':' || n.title || coalesce(n.content, n.body, ''), 'UTF8'), 'sha256'), 'hex'),
  '7930b6fd6053ffc4fbb54696025b826224f7c6002b350360b95d9611c9d19f93',
  'baseline_verified'
from public.notes n
where n.id = '416b0775-2da4-43da-bd59-eb1cea2f9d6c'
  and n.owner_id = '92b93459-4560-49f8-b51a-e159b4478c0c'
  and n.title = 'TEST_MEMO'
  and coalesce(n.content, n.body, '') = '사용자 B 테스트 메모입니다.'
on conflict (note_id) do nothing;
