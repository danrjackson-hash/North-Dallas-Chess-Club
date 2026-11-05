-- North Dallas Chess Club: initial shared-database schema
-- Apply in Supabase SQL Editor. All player-facing data is scoped to authenticated users.
create extension if not exists pgcrypto;

create table if not exists public.club_settings (
  id boolean primary key default true check (id),
  club_name text not null default 'North Dallas Chess Club',
  default_rating integer not null default 1400 check (default_rating between 100 and 4000),
  k_factor integer not null default 20 check (k_factor between 1 and 100),
  updated_at timestamptz not null default now()
);
insert into public.club_settings (id) values (true) on conflict (id) do nothing;

create table if not exists public.players (
  id uuid primary key default gen_random_uuid(),
  display_name text not null check (length(trim(display_name)) between 1 and 80),
  starting_rating integer not null default 1400 check (starting_rating between 100 and 4000),
  current_rating integer not null default 1400 check (current_rating between 0 and 10000),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  role text not null default 'player' check (role in ('player','admin')),
  player_id uuid unique references public.players(id) on delete set null,
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'), ''),
             split_part(coalesce(new.email, 'Player'), '@', 1))
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_club_admin()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  );
$$;

create table if not exists public.games (
  id uuid primary key default gen_random_uuid(),
  white_player_id uuid not null references public.players(id),
  black_player_id uuid not null references public.players(id),
  result text not null check (result in ('white_win','draw','black_win')),
  played_at timestamptz not null,
  source_submission_id uuid unique,
  entered_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  voided_at timestamptz,
  voided_by uuid references auth.users(id) on delete set null,
  void_reason text,
  constraint different_players check (white_player_id <> black_player_id)
);

create table if not exists public.game_submissions (
  id uuid primary key default gen_random_uuid(),
  submitted_by uuid not null references auth.users(id) on delete restrict,
  white_player_id uuid not null references public.players(id),
  black_player_id uuid not null references public.players(id),
  result text not null check (result in ('white_win','draw','black_win')),
  played_at timestamptz not null,
  comments text check (comments is null or length(comments) <= 1000),
  status text not null default 'pending' check (status in ('pending','approved','rejected','needs_review')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  review_note text,
  created_at timestamptz not null default now(),
  constraint submission_different_players check (white_player_id <> black_player_id)
);

alter table public.games
  drop constraint if exists games_source_submission_id_fkey;
alter table public.games
  add constraint games_source_submission_id_fkey
  foreign key (source_submission_id) references public.game_submissions(id) on delete set null;

create table if not exists public.rating_history (
  id bigint generated always as identity primary key,
  player_id uuid not null references public.players(id) on delete cascade,
  game_id uuid not null references public.games(id) on delete cascade,
  rating_before integer not null,
  rating_change integer not null,
  rating_after integer not null,
  calculated_at timestamptz not null default now(),
  unique (player_id, game_id)
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null,
  message text not null,
  submission_id uuid references public.game_submissions(id) on delete cascade,
  created_at timestamptz not null default now(),
  read_at timestamptz
);

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  actor_user_id uuid references auth.users(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists players_active_name_idx on public.players (is_active, display_name);
create index if not exists games_played_at_idx on public.games (played_at, created_at) where voided_at is null;
create index if not exists submissions_status_idx on public.game_submissions (status, created_at desc);
create index if not exists notifications_recipient_idx on public.notifications (recipient_user_id, created_at desc);

alter table public.club_settings enable row level security;
alter table public.players enable row level security;
alter table public.profiles enable row level security;
alter table public.games enable row level security;
alter table public.game_submissions enable row level security;
alter table public.rating_history enable row level security;
alter table public.notifications enable row level security;
alter table public.audit_log enable row level security;

drop policy if exists "settings readable by signed-in users" on public.club_settings;
create policy "settings readable by signed-in users" on public.club_settings
for select to authenticated using (true);
drop policy if exists "settings managed by admins" on public.club_settings;
create policy "settings managed by admins" on public.club_settings
for update to authenticated using (public.is_club_admin()) with check (public.is_club_admin());

drop policy if exists "active roster readable by signed-in users" on public.players;
create policy "active roster readable by signed-in users" on public.players
for select to authenticated using (is_active or public.is_club_admin());
drop policy if exists "players managed by admins" on public.players;
create policy "players managed by admins" on public.players
for all to authenticated using (public.is_club_admin()) with check (public.is_club_admin());

drop policy if exists "profiles visible to self or admins" on public.profiles;
create policy "profiles visible to self or admins" on public.profiles
for select to authenticated using (id = (select auth.uid()) or public.is_club_admin());
drop policy if exists "profiles updated by self or admins" on public.profiles;
drop policy if exists "profiles managed by admins" on public.profiles;
create policy "profiles managed by admins" on public.profiles
for update to authenticated using (public.is_club_admin())
with check (public.is_club_admin());

drop policy if exists "approved games readable by signed-in users" on public.games;
create policy "approved games readable by signed-in users" on public.games
for select to authenticated using (voided_at is null or public.is_club_admin());
drop policy if exists "games managed by admins" on public.games;
create policy "games managed by admins" on public.games
for all to authenticated using (public.is_club_admin()) with check (public.is_club_admin());

drop policy if exists "submissions visible to participants or admins" on public.game_submissions;
create policy "submissions visible to participants or admins" on public.game_submissions
for select to authenticated using (
  submitted_by = (select auth.uid())
  or public.is_club_admin()
  or exists (select 1 from public.profiles p where p.id = (select auth.uid())
             and p.player_id in (white_player_id, black_player_id))
);
drop policy if exists "players may submit their own games" on public.game_submissions;
create policy "players may submit their own games" on public.game_submissions
for insert to authenticated with check (
  submitted_by = (select auth.uid())
  and exists (select 1 from public.profiles p where p.id = (select auth.uid())
              and p.player_id in (white_player_id, black_player_id))
  and exists (select 1 from public.players w where w.id = white_player_id and w.is_active)
  and exists (select 1 from public.players b where b.id = black_player_id and b.is_active)
);
drop policy if exists "rating history readable by signed-in users" on public.rating_history;
create policy "rating history readable by signed-in users" on public.rating_history
for select to authenticated using (true);
drop policy if exists "notifications readable by recipient" on public.notifications;
create policy "notifications readable by recipient" on public.notifications
for select to authenticated using (recipient_user_id = (select auth.uid()));
drop policy if exists "notifications marked read by recipient" on public.notifications;
create policy "notifications marked read by recipient" on public.notifications
for update to authenticated using (recipient_user_id = (select auth.uid()))
with check (recipient_user_id = (select auth.uid()));
drop policy if exists "audit log visible to admins" on public.audit_log;
create policy "audit log visible to admins" on public.audit_log
for select to authenticated using (public.is_club_admin());

-- Rebuild the rating ledger in played-date order so late-entered games are handled consistently.
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
  update public.players set current_rating = starting_rating;
  delete from public.rating_history;

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

-- A player can approve/reject a result involving them, but never their own submission.
-- Admins can review any submission. Approval, official-game creation, ratings and notices
-- all happen in one transaction.
create or replace function public.review_game_submission(
  p_submission_id uuid,
  p_approve boolean,
  p_note text default null
)
returns void language plpgsql security definer set search_path = public
as $$
declare
  s public.game_submissions%rowtype;
  reviewer_player uuid;
  submitter_player uuid;
  opponent_user uuid;
  new_game_id uuid;
begin
  select * into s from public.game_submissions
  where id = p_submission_id for update;

  if not found then raise exception 'Submission not found'; end if;
  if s.status <> 'pending' and s.status <> 'needs_review' then
    raise exception 'This submission has already been reviewed';
  end if;
  if auth.uid() is null or auth.uid() = s.submitted_by then
    raise exception 'You cannot review your own submission';
  end if;

  select player_id into reviewer_player from public.profiles where id = auth.uid();
  if not public.is_club_admin()
     and (reviewer_player is null or reviewer_player not in (s.white_player_id, s.black_player_id)) then
    raise exception 'Only the opponent or a club admin can review this result';
  end if;

  if p_approve then
    insert into public.games
      (white_player_id, black_player_id, result, played_at, source_submission_id, entered_by)
    values
      (s.white_player_id, s.black_player_id, s.result, s.played_at, s.id, s.submitted_by)
    returning id into new_game_id;

    update public.game_submissions
      set status = 'approved', reviewed_by = auth.uid(), reviewed_at = now(),
          review_note = null
      where id = s.id;

    perform public.recalculate_ratings();

    insert into public.audit_log (actor_user_id, action, entity_type, entity_id, details)
    values (auth.uid(), 'submission_approved', 'game_submission', s.id,
            jsonb_build_object('game_id', new_game_id));
  else
    update public.game_submissions
      set status = 'rejected', reviewed_by = auth.uid(), reviewed_at = now(),
          review_note = left(coalesce(p_note, 'Result rejected'), 1000)
      where id = s.id;

    insert into public.audit_log (actor_user_id, action, entity_type, entity_id, details)
    values (auth.uid(), 'submission_rejected', 'game_submission', s.id,
            jsonb_build_object('note', left(coalesce(p_note, 'Result rejected'), 1000)));
  end if;

  select player_id into submitter_player from public.profiles where id = s.submitted_by;
  select id into opponent_user from public.profiles
    where player_id = case when submitter_player = s.white_player_id then s.black_player_id
                           else s.white_player_id end;
  insert into public.notifications (recipient_user_id, kind, message, submission_id)
  values (s.submitted_by,
          case when p_approve then 'submission_approved' else 'submission_rejected' end,
          case when p_approve then 'Your game result was approved.'
               else 'Your game result was rejected: ' || coalesce(p_note, 'Please contact the club admin.') end,
          s.id);
  if opponent_user is not null and opponent_user <> auth.uid() then
    insert into public.notifications (recipient_user_id, kind, message, submission_id)
    values (opponent_user,
            case when p_approve then 'game_approved' else 'game_rejected' end,
            case when p_approve then 'A submitted game involving you was approved.'
                 else 'A submitted game involving you was rejected.' end,
            s.id);
  end if;
end;
$$;

revoke all on function public.is_club_admin() from public, anon;
grant execute on function public.is_club_admin() to authenticated;
revoke all on function public.recalculate_ratings() from public, anon, authenticated;
revoke all on function public.review_game_submission(uuid, boolean, text) from public, anon;
grant execute on function public.review_game_submission(uuid, boolean, text) to authenticated;
