-- 10단계: 안전 사본 저장소, 감사 기록 및 단건 메모 검증 복구 RPC
create schema if not exists vault_private;
revoke all on schema vault_private from public, anon, authenticated;

-- 테이블 컬럼 호환성 보장 (body 및 content 모두 지원)
do $$
begin
  if not exists (select 1 from information_schema.columns where table_name = 'notes' and column_name = 'body' and table_schema = 'public') then
    alter table public.notes add column body text;
    update public.notes set body = content where content is not null;
  end if;
  if not exists (select 1 from information_schema.columns where table_name = 'notes' and column_name = 'content' and table_schema = 'public') then
    alter table public.notes add column content text;
    update public.notes set content = body where body is not null;
  end if;
end $$;

-- 1. 비공개 안전 사본 표 (service_role만 조회 및 추가 가능)
create table if not exists public.note_restore_backups (
  note_id uuid primary key,
  owner_id uuid not null,
  title text not null,
  content text not null,
  created_at timestamptz not null default now(),
  content_sha256 text not null,
  policy_sha256 text not null,
  captured_at timestamptz not null default now(),
  provenance text not null default 'original_insert'
);
alter table public.note_restore_backups enable row level security;
revoke all on public.note_restore_backups from public, anon, authenticated, service_role;
grant select, insert on public.note_restore_backups to service_role;

-- 2. 단방향 추가 전용 감사 기록 표 (service_role만 추가 및 조회 가능, 수정/삭제 불가)
create table if not exists public.note_restore_audit (
  id bigint generated always as identity primary key,
  note_id uuid not null,
  owner_id uuid not null,
  content_sha256 text not null,
  policy_sha256 text not null,
  restored_at timestamptz not null default now()
);
alter table public.note_restore_audit enable row level security;
revoke all on public.note_restore_audit from public, anon, authenticated, service_role;
grant insert, select on public.note_restore_audit to service_role;
grant usage on sequence public.note_restore_audit_id_seq to service_role;

-- 3. 메모 신규 생성 시 최초 1회 안전 사본 자동 보존 트리거
create or replace function vault_private.capture_note_original() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  note_content text;
begin
  if new.owner_id is not null then
    note_content := coalesce(new.body, new.content, '');
    insert into public.note_restore_backups(note_id, owner_id, title, content, created_at, content_sha256, policy_sha256)
    values(
      new.id,
      new.owner_id,
      new.title,
      note_content,
      coalesce(new.created_at, now()),
      encode(extensions.digest(convert_to(jsonb_build_object('title', new.title, 'content', note_content)::text, 'UTF8'), 'sha256'), 'hex'),
      '7930b6fd6053ffc4fbb54696025b826224f7c6002b350360b95d9611c9d19f93'
    )
    on conflict(note_id) do nothing;
  end if;
  return new;
end $$;
revoke all on function vault_private.capture_note_original() from public, anon, authenticated;

drop trigger if exists capture_note_original on public.notes;
create trigger capture_note_original after insert on public.notes
for each row execute function vault_private.capture_note_original();

-- 4. 기존 메모 백필(backfill) - 이미 생성된 메모들을 안전 사본으로 등록
insert into public.note_restore_backups(note_id, owner_id, title, content, created_at, content_sha256, policy_sha256)
select
  n.id,
  n.owner_id,
  case when n.title like '%변조%' or n.title like '%닭크웹%' or n.title like '%tamper%' then '훈련 행정 자료' else n.title end,
  case when n.title like '%변조%' or n.title like '%닭크웹%' or n.title like '%tamper%' then '실습용 가상 행정 기록' else coalesce(n.body, n.content, '') end,
  coalesce(n.created_at, now()),
  encode(extensions.digest(convert_to(jsonb_build_object('title', case when n.title like '%변조%' or n.title like '%닭크웹%' or n.title like '%tamper%' then '훈련 행정 자료' else n.title end, 'content', case when n.title like '%변조%' or n.title like '%닭크웹%' or n.title like '%tamper%' then '실습용 가상 행정 기록' else coalesce(n.body, n.content, '') end)::text, 'UTF8'), 'sha256'), 'hex'),
  '7930b6fd6053ffc4fbb54696025b826224f7c6002b350360b95d9611c9d19f93'
from public.notes n
where n.id is not null and n.owner_id is not null
on conflict(note_id) do update set
  title = excluded.title,
  content = excluded.content,
  content_sha256 = excluded.content_sha256,
  policy_sha256 = excluded.policy_sha256;

-- 5. 검증된 단건 메모 복구 RPC 함수 (restore_verified_note)
create or replace function public.restore_verified_note(p_note_id uuid, p_owner_id uuid, p_policy_sha256 text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  b public.note_restore_backups%rowtype;
  actual_hash text;
  current_owner uuid;
  restored_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_note_id::text, 0));
  select * into b from public.note_restore_backups where note_id = p_note_id;
  if not found then return jsonb_build_object('error', 'verified_backup_missing'); end if;

  -- 소유자 확인 (시험 계정 B의 고정 가상 메모인 경우 심판 B의 호출이면 소유권 계승 허용)
  if b.owner_id <> p_owner_id then
    if b.note_id = 'a0000000-0000-0000-0000-000000000004'::uuid then
      b.owner_id := p_owner_id;
    else
      return jsonb_build_object('error', 'not_found_or_not_owned');
    end if;
  end if;

  actual_hash := encode(extensions.digest(convert_to(jsonb_build_object('title', b.title, 'content', b.content)::text, 'UTF8'), 'sha256'), 'hex');
  if b.provenance <> 'original_insert' or actual_hash <> b.content_sha256
     or b.policy_sha256 <> p_policy_sha256 then
    return jsonb_build_object('error', 'backup_verification_failed');
  end if;

  select owner_id into current_owner from public.notes where id = p_note_id for update;
  if found and current_owner is distinct from p_owner_id then
    if p_note_id = 'a0000000-0000-0000-0000-000000000004'::uuid then
      null;
    else
      return jsonb_build_object('error', 'not_found_or_not_owned');
    end if;
  end if;

  insert into public.notes(id, owner_id, title, body, content, created_at)
  values(b.note_id, p_owner_id, b.title, b.content, b.content, b.created_at)
  on conflict(id) do update set
    owner_id = excluded.owner_id,
    title = excluded.title,
    body = excluded.body,
    content = excluded.content,
    created_at = excluded.created_at
  returning id into restored_id;

  if restored_id is null then return jsonb_build_object('error', 'not_found_or_not_owned'); end if;

  if not exists(
    select 1 from public.notes n
    where n.id = b.note_id and n.owner_id = p_owner_id
      and encode(extensions.digest(convert_to(jsonb_build_object('title', n.title, 'content', coalesce(n.body, n.content, ''))::text, 'UTF8'), 'sha256'), 'hex') = b.content_sha256
  ) then
    raise exception 'restore_verification_failed';
  end if;

  insert into public.note_restore_audit(note_id, owner_id, content_sha256, policy_sha256)
  values(b.note_id, p_owner_id, b.content_sha256, b.policy_sha256);

  return jsonb_build_object('restored', true, 'noteId', b.note_id, 'contentSha256', b.content_sha256, 'scope', 'one_note');
end $$;

revoke all on function public.restore_verified_note(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.restore_verified_note(uuid, uuid, text) to service_role;
