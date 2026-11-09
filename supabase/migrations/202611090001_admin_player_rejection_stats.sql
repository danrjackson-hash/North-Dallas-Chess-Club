create or replace function public.admin_player_rejection_stats()
returns table (
  player_id uuid,
  display_name text,
  rejected_count bigint,
  games_played bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_club_admin() then
    raise exception 'Only club administrators may view rejection statistics';
  end if;

  return query
  select
    p.id,
    p.display_name,
    count(distinct gs.id) filter (where gs.status = 'rejected') as rejected_count,
    count(distinct g.id) filter (where g.voided_at is null) as games_played
  from public.players p
  left join public.profiles pr on pr.player_id = p.id
  left join public.game_submissions gs
    on gs.reviewed_by = pr.id
   and gs.status = 'rejected'
  left join public.games g
    on (g.white_player_id = p.id or g.black_player_id = p.id)
   and g.voided_at is null
  where p.is_active = true
  group by p.id, p.display_name
  order by p.display_name;
end;
$$;

revoke all on function public.admin_player_rejection_stats() from public, anon, authenticated;
grant execute on function public.admin_player_rejection_stats() to authenticated;
