create table if not exists public.judge_request_trace (
 id bigint generated always as identity primary key,
 ts timestamptz not null default now(),
 route text, method text, login_kind text, identity text, user_id text,
 note_id text, status int, reason text
);
alter table public.judge_request_trace enable row level security;
revoke all on public.judge_request_trace from public, anon, authenticated, service_role;
grant insert, select on public.judge_request_trace to service_role;
grant usage on sequence public.judge_request_trace_id_seq to service_role;
