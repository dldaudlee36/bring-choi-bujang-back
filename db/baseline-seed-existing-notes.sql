-- 일회성: 트리거 설치 전에 만들어진 기존 메모(시험 계정 A, B 포함)를 침해 전 기준 사본으로 한 번 남긴다.
-- 이미 사본이 있는 메모는 건너뛴다(on conflict do nothing). 변조가 확인된 메모가 있으면 이 스크립트를 실행하지 말고 먼저 원본을 확인한다.
-- 출처는 'baseline_verified'로 구분한다. 실행 전 아래 [확인] 쿼리로 사본이 없는 메모 목록과 내용을 눈으로 확인한다.
--
-- [확인] select id, owner_id, title, left(coalesce(content, body, ''), 40) from public.notes n
--        where owner_id is not null and not exists (select 1 from public.note_restore_backups b where b.note_id = n.id);
insert into public.note_restore_backups(note_id, owner_id, title, content, created_at, content_sha256, policy_sha256, provenance)
select n.id, n.owner_id, n.title, coalesce(n.content, n.body, ''), coalesce(n.created_at, now()),
  encode(extensions.digest(convert_to(octet_length(convert_to(n.title, 'UTF8'))::text || ':' || n.title || coalesce(n.content, n.body, ''), 'UTF8'), 'sha256'), 'hex'),
  '7930b6fd6053ffc4fbb54696025b826224f7c6002b350360b95d9611c9d19f93',
  'baseline_verified'
from public.notes n
where n.owner_id is not null
on conflict (note_id) do nothing;
