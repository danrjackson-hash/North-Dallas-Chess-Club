create or replace function public.admin_update_player_name(
  p_player_id uuid,
  p_display_name text
)
returns void
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  clean_name text;
begin
  if auth.uid() is null or not public.is_club_admin() then
    raise exception 'Only a club admin can edit player names';
  end if;

  clean_name := trim(coalesce(p_display_name, ''));
  if length(clean_name) < 1 or length(clean_name) > 80 then
    raise exception 'Player names must be between 1 and 80 characters';
  end if;

  update public.players
  set display_name = clean_name
  where id = p_player_id;

  if not found then
    raise exception 'Player not found';
  end if;

  update public.profiles
  set display_name = clean_name
  where player_id = p_player_id;

  insert into public.audit_log(actor_user_id, action, entity_type, entity_id, details)
  values (
    auth.uid(),
    'player_name_updated',
    'player',
    p_player_id,
    jsonb_build_object('new_display_name', clean_name)
  );
end;
$function$;

revoke all on function public.admin_update_player_name(uuid, text) from public, anon;
grant execute on function public.admin_update_player_name(uuid, text) to authenticated;
