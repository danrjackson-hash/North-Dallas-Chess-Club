-- Public registration is now accepted only through the Edge Function.
revoke insert on table public.registration_requests from anon, authenticated;
drop policy if exists "public may submit registration requests" on public.registration_requests;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.registration_rate_limits (
  ip_hash text not null,
  window_start timestamptz not null,
  request_count integer not null default 0 check (request_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (ip_hash, window_start)
);
alter table private.registration_rate_limits enable row level security;
revoke all on table private.registration_rate_limits from public, anon, authenticated;

create or replace function public.consume_registration_rate_limit(p_ip_hash text)
returns boolean
language plpgsql
security definer
set search_path = private, pg_temp
as $$
declare
  current_window timestamptz := date_trunc('hour', now());
  current_count integer;
begin
  if p_ip_hash is null or length(p_ip_hash) <> 64 or p_ip_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid rate-limit key';
  end if;

  insert into private.registration_rate_limits(ip_hash, window_start, request_count, updated_at)
  values (p_ip_hash, current_window, 1, now())
  on conflict (ip_hash, window_start)
  do update set request_count = private.registration_rate_limits.request_count + 1,
                updated_at = now()
  returning request_count into current_count;

  delete from private.registration_rate_limits
  where window_start < now() - interval '48 hours';

  return current_count <= 10;
end;
$$;

revoke all on function public.consume_registration_rate_limit(text) from public, anon, authenticated;
grant execute on function public.consume_registration_rate_limit(text) to service_role;
