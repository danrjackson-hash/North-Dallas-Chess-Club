-- Self-service registration: store only a hash of the club access code.
create table if not exists public.club_registration_secrets (
  id boolean primary key default true check (id),
  code_hash text,
  updated_at timestamptz not null default now(),
  constraint club_registration_code_hash_format check (code_hash is null or code_hash ~ '^[0-9a-f]{64}$')
);
insert into public.club_registration_secrets (id) values (true) on conflict (id) do nothing;
alter table public.club_registration_secrets enable row level security;
revoke all on public.club_registration_secrets from public, anon, authenticated;
grant all on public.club_registration_secrets to service_role;

alter table public.registration_requests
  drop constraint if exists registration_requests_status_check;
alter table public.registration_requests
  add constraint registration_requests_status_check
  check (status in ('pending', 'awaiting_verification', 'approved', 'rejected'));
drop index if exists public.registration_requests_one_pending_email;
create unique index registration_requests_one_unresolved_email
  on public.registration_requests (lower(trim(email)))
  where status in ('pending', 'awaiting_verification');

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create or replace function private.finalize_club_registration(p_user_id uuid)
returns uuid language plpgsql security definer set search_path = ''
as $function$
declare
  v_email text;
  v_confirmed_at timestamptz;
  v_request public.registration_requests%rowtype;
  v_existing_player uuid;
  v_player_id uuid;
  v_rating integer;
begin
  select u.email, u.email_confirmed_at into v_email, v_confirmed_at
  from auth.users u where u.id = p_user_id;
  if v_email is null or v_confirmed_at is null then return null; end if;

  select p.player_id into v_existing_player
  from public.profiles p where p.id = p_user_id for update;
  if v_existing_player is not null then return v_existing_player; end if;

  select * into v_request
  from public.registration_requests r
  where lower(trim(r.email)) = lower(trim(v_email))
    and r.status = 'awaiting_verification' and r.player_id is null
  order by r.submitted_at desc limit 1 for update;
  if not found then return null; end if;

  v_rating := case v_request.skill_level
    when 'Beginner' then 1000 when 'Intermediate' then 1400
    when 'Advanced' then 1800 when 'Expert' then 2200 else 1400 end;

  insert into public.players (display_name, starting_rating, current_rating, is_active, created_by)
  values (trim(v_request.full_name), v_rating, v_rating, true, p_user_id)
  returning id into v_player_id;

  update public.registration_requests
  set status='approved', reviewed_at=now(), reviewed_by=null, player_id=v_player_id
  where id=v_request.id;

  insert into public.profiles (id, display_name, email, player_id)
  values (p_user_id, trim(v_request.full_name), lower(trim(v_email)), v_player_id)
  on conflict (id) do update
    set display_name=excluded.display_name, email=excluded.email,
        player_id=coalesce(public.profiles.player_id, excluded.player_id);

  insert into public.audit_log (actor_user_id, action, entity_type, entity_id, details)
  values (p_user_id, 'registration_self_service_completed', 'registration_request', v_request.id,
          jsonb_build_object('player_id',v_player_id,'skill_level',v_request.skill_level,'starting_rating',v_rating));
  return v_player_id;
end;
$function$;

create or replace function private.activate_verified_registration()
returns trigger language plpgsql security definer set search_path = ''
as $function$
begin
  if old.email_confirmed_at is null and new.email_confirmed_at is not null then
    perform private.finalize_club_registration(new.id);
  end if;
  return new;
end;
$function$;

drop trigger if exists on_auth_user_email_confirmed on auth.users;
create trigger on_auth_user_email_confirmed
after update of email_confirmed_at on auth.users
for each row
when (old.email_confirmed_at is null and new.email_confirmed_at is not null)
execute function private.activate_verified_registration();

create or replace function public.complete_self_registration()
returns uuid language plpgsql security definer set search_path = ''
as $function$
declare v_user_id uuid := auth.uid();
begin
  if v_user_id is null then raise exception 'You must be signed in to complete registration'; end if;
  return private.finalize_club_registration(v_user_id);
end;
$function$;
revoke all on function public.complete_self_registration() from public, anon;
grant execute on function public.complete_self_registration() to authenticated;

create or replace function public.admin_set_club_registration_code(p_code_hash text)
returns void language plpgsql security definer set search_path = ''
as $function$
begin
  if auth.uid() is null or not public.is_club_admin() then
    raise exception 'Only a club admin can change the registration access code';
  end if;
  if p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid registration code hash';
  end if;
  insert into public.club_registration_secrets (id, code_hash, updated_at)
  values (true, p_code_hash, now())
  on conflict (id) do update set code_hash=excluded.code_hash, updated_at=excluded.updated_at;
  insert into public.audit_log (actor_user_id, action, entity_type, details)
  values (auth.uid(), 'registration_access_code_rotated', 'club_settings', jsonb_build_object('updated_at',now()));
end;
$function$;
revoke all on function public.admin_set_club_registration_code(text) from public, anon;
grant execute on function public.admin_set_club_registration_code(text) to authenticated;
