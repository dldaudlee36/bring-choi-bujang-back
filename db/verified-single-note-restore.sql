create schema if not exists vault_private;
revoke all on schema vault_private from public, anon, authenticated;

create table if not exists public.note_restore_backups (
  note_id uuid primary key,
  owner_id uuid not null,
  title text not null,
  body text not null,
  created_at timestamptz not null default now(),
  content_sha256 text not null,
  policy_sha256 text not null,
  captured_at timestamptz not null default now(),
  provenance text not null default 'original_insert'
);
alter table public.note_restore_backups enable row level security;
revoke all on public.note_restore_backups from public, anon, authenticated, service_role;
grant select on public.note_restore_backups to service_role;

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
  if b.owner_id <> p_owner_id then return jsonb_build_object('error', 'not_found_or_not_owned'); end if;

  actual_hash := encode(extensions.digest(convert_to(jsonb_build_object('title', b.title, 'body', b.body)::text, 'UTF8'), 'sha256'), 'hex');
  if b.provenance <> 'original_insert' or actual_hash <> b.content_sha256
     or b.policy_sha256 <> p_policy_sha256 then
    return jsonb_build_object('error', 'backup_verification_failed');
  end if;

  select owner_id into current_owner from public.notes where id = p_note_id for update;
  if found and current_owner is distinct from p_owner_id then
    return jsonb_build_object('error', 'not_found_or_not_owned');
  end if;

  insert into public.notes(id, owner_id, title, body, created_at)
  values(b.note_id, b.owner_id, b.title, b.body, b.created_at)
  on conflict(id) do update set title = excluded.title, body = excluded.body, created_at = excluded.created_at
  where notes.owner_id = p_owner_id
  returning id into restored_id;

  if restored_id is null then return jsonb_build_object('error', 'not_found_or_not_owned'); end if;

  insert into public.note_restore_audit(note_id, owner_id, content_sha256, policy_sha256)
  values(b.note_id, b.owner_id, b.content_sha256, b.policy_sha256);

  return jsonb_build_object('restored', true, 'noteId', b.note_id, 'contentSha256', b.content_sha256, 'scope', 'one_note');
end $$;

revoke all on function public.restore_verified_note(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.restore_verified_note(uuid, uuid, text) to service_role;
