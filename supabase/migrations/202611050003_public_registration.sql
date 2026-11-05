-- Public QR-code registration requests; no account or roster entry is created until an admin approves.
create table if not exists public.registration_requests (
  id uuid primary key default gen_random_uuid(),
  full_name text not null check (length(trim(full_name)) between 1 and 80),
  email text not null check (length(trim(email)) between 5 and 254),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  submitted_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id) on delete set null,
  player_id uuid references public.players(id) on delete set null
);

create index if not exists registration_requests_status_idx
  on public.registration_requests(status, submitted_at desc);
create unique index if not exists registration_requests_one_pending_email
  on public.registration_requests(lower(email)) where status = 'pending';

alter table public.registration_requests enable row level security;

drop policy if exists "public may submit registration requests" on public.registration_requests;
create policy "public may submit registration requests" on public.registration_requests
for insert to anon, authenticated
with check (
  status = 'pending'
  and reviewed_at is null
  and reviewed_by is null
  and player_id is null
  and length(trim(full_name)) between 1 and 80
  and length(trim(email)) between 5 and 254
);

drop policy if exists "admins may read registration requests" on public.registration_requests;
create policy "admins may read registration requests" on public.registration_requests
for select to authenticated using (public.is_club_admin());

grant insert on public.registration_requests to anon, authenticated;
grant select on public.registration_requests to authenticated;

create or replace function public.review_registration_request(
  p_request_id uuid,
  p_approve boolean
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.registration_requests%rowtype;
  new_player_id uuid;
begin
  if auth.uid() is null or not public.is_club_admin() then
    raise exception 'Only a club admin can review registration requests';
  end if;

  select * into r
  from public.registration_requests
  where id = p_request_id
  for update;

  if not found then raise exception 'Registration request not found'; end if;
  if r.status <> 'pending' then raise exception 'This registration request has already been reviewed'; end if;

  if p_approve then
    insert into public.players (display_name, starting_rating, current_rating, is_active, created_by)
    values (trim(r.full_name), 1400, 1400, true, auth.uid())
    returning id into new_player_id;

    update public.registration_requests
    set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid(), player_id = new_player_id
    where id = r.id;

    insert into public.audit_log(actor_user_id, action, entity_type, entity_id, details)
    values (auth.uid(), 'registration_approved', 'registration_request', r.id,
            jsonb_build_object('player_id', new_player_id, 'email', lower(trim(r.email))));
  else
    update public.registration_requests
    set status = 'rejected', reviewed_at = now(), reviewed_by = auth.uid()
    where id = r.id;

    insert into public.audit_log(actor_user_id, action, entity_type, entity_id, details)
    values (auth.uid(), 'registration_rejected', 'registration_request', r.id,
            jsonb_build_object('email', lower(trim(r.email))));
  end if;

  return new_player_id;
end;
$$;

revoke all on function public.review_registration_request(uuid, boolean) from public, anon;
grant execute on function public.review_registration_request(uuid, boolean) to authenticated;
