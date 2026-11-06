-- Apply the requested skill-level rating when an administrator approves registration.
-- Preserve the existing admin check, locking, status handling, and audit trail.
create or replace function public.review_registration_request(
  p_request_id uuid,
  p_approve boolean
)
returns uuid
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  r public.registration_requests%rowtype;
  new_player_id uuid;
  initial_rating integer;
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
    initial_rating := case r.skill_level
      when 'Beginner' then 1000
      when 'Intermediate' then 1400
      when 'Advanced' then 1800
      when 'Expert' then 2200
      else 1400
    end;

    insert into public.players (display_name, starting_rating, current_rating, is_active, created_by)
    values (trim(r.full_name), initial_rating, initial_rating, true, auth.uid())
    returning id into new_player_id;

    update public.registration_requests
    set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid(), player_id = new_player_id
    where id = r.id;

    insert into public.audit_log(actor_user_id, action, entity_type, entity_id, details)
    values (auth.uid(), 'registration_approved', 'registration_request', r.id,
            jsonb_build_object('player_id', new_player_id, 'email', lower(trim(r.email)),
                               'skill_level', r.skill_level, 'starting_rating', initial_rating));
  else
    update public.registration_requests
    set status = 'rejected', reviewed_at = now(), reviewed_by = auth.uid()
    where id = r.id;

    insert into public.audit_log(actor_user_id, action, entity_type, entity_id, details)
    values (auth.uid(), 'registration_rejected', 'registration_request', r.id,
            jsonb_build_object('email', lower(trim(r.email)), 'skill_level', r.skill_level));
  end if;

  return new_player_id;
end;
$function$;

revoke all on function public.review_registration_request(uuid, boolean) from public, anon;
grant execute on function public.review_registration_request(uuid, boolean) to authenticated;
