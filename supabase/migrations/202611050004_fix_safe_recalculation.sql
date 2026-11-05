-- Fix rating recalculation for databases enforcing safe UPDATE/DELETE statements.
-- The function intentionally resets all players and rebuilds the ledger, so use explicit WHERE true.

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
  update public.players set current_rating = starting_rating where true;
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
