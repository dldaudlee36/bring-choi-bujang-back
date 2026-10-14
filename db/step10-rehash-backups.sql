-- 일회성 이전: 기존 사본의 지문을 새 방식(제목바이트수:제목본문)으로 다시 계산해 저장한다.
-- 사본의 제목과 본문은 바꾸지 않는다. 지문만 다시 계산하므로, 실행 전에 사본 내용이 원본인지 확인한다.
-- 실행 순서: 1) db/verified-single-note-restore.sql  2) 이 파일  3) (필요하면) db/baseline-seed-existing-notes.sql
update public.note_restore_backups
   set content_sha256 = encode(extensions.digest(convert_to(octet_length(convert_to(title, 'UTF8'))::text || ':' || title || content, 'UTF8'), 'sha256'), 'hex');

-- [확인] 모든 사본의 지문이 새 방식으로 일치해야 한다(mismatch가 0이어야 정상).
select count(*) as backups,
       count(*) filter (where content_sha256 <> encode(extensions.digest(convert_to(octet_length(convert_to(title, 'UTF8'))::text || ':' || title || content, 'UTF8'), 'sha256'), 'hex')) as mismatch
  from public.note_restore_backups;
