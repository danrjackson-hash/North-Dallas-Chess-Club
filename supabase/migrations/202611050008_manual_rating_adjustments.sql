-- Allow admins to make durable manual rating adjustments.
-- Adjustments are added to the player's baseline so later game-ledger rebuilds preserve them.
alter table public.players
  add column if not exists rating_adjustment integer not null default 0;

create or replace function public.recalculate_ratings()
returns void language plpgsql security definer set search_path = public
as $$
declare
  g record;
  white_rating integer;
  black_rating integer;
  expected_white numeric;
  actual_white numeric;
  delta integer;
  k integer;
begin
  select k_factor into k from public.club_settings where id = true;
  update public.players
    set current_rating = starting_rating + rating_adjustment
    where true;
  delete from public.rating_history where true;

  for g in
    select * from public.games
    where voided_at is null
    order by played_at asc, created_at asc, id asc
  loop
    select current_rating into white_rating from public.players where id = g.white_player_id;
    select current_rating into black_rating from public.players where id = g.black_player_id;
    if white_rating is null or black_rating is null then
      continue;
    end if;

    expected_white := 1 / (1 + power(10::numeric, (black_rating - white_rating)::numeric / 400));
    actual_white := case g.result when 'white_win' then 1 when 'draw' then 0.5 else 0 end;
    delta := round(k * (actual_white - expected_white))::integer;

    update public.players set current_rating = current_rating + delta where id = g.white_player_id;
    update public.players set current_rating = current_rating - delta where id = g.black_player_id;

    insert into public.rating_history (player_id, game_id, rating_before, rating_change, rating_after)
    values
      (g.white_player_id, g.id, white_rating, delta, white_rating + delta),
      (g.black_player_id, g.id, black_rating, -delta, black_rating - delta);
  end loop;
end;
$$;

create or replace function public.admin_set_player_rating(
  p_player_id uuid,
  p_new_rating integer
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  player_row public.players%rowtype;
  adjustment_delta integer;
begin
  if auth.uid() is null or not public.is_club_admin() then
    raise exception 'Only a club admin can change player ratings';
  end if;

  if p_new_rating is null or p_new_rating < 100 or p_new_rating > 4000 then
    raise exception 'Rating must be a whole number between 100 and 4000';
  end if;

  select * into player_row
  from public.players
  where id = p_player_id
  for update;

  if not found then
    raise exception 'Player not found';
  end if;

  adjustment_delta := p_new_rating - player_row.current_rating;

  update public.players
  set rating_adjustment = rating_adjustment + adjustment_delta
  where id = p_player_id;

  perform public.recalculate_ratings();

  insert into public.audit_log (actor_user_id, action, entity_type, entity_id, details)
  values (
    auth.uid(),
    'player_rating_manually_adjusted',
    'player',
    p_player_id,
    jsonb_build_object(
      'player_name', player_row.display_name,
      'previous_rating', player_row.current_rating,
      'new_rating', p_new_rating,
      'adjustment', adjustment_delta
    )
  );
end;
$$;

revoke all on function public.admin_set_player_rating(uuid, integer) from public, anon;
grant execute on function public.admin_set_player_rating(uuid, integer) to authenticated;
