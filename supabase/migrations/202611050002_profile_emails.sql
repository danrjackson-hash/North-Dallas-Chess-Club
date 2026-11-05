-- Add email visibility for admins so invited accounts can be matched safely.
alter table public.profiles add column if not exists email text;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, display_name, email)
  values (
    new.id,
    coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'), ''),
             split_part(coalesce(new.email, 'Player'), '@', 1)),
    new.email
  )
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

-- Backfill emails for accounts that already existed when the initial schema was installed.
update public.profiles p
set email = u.email
from auth.users u
where p.id = u.id and p.email is distinct from u.email;

create index if not exists profiles_email_lower_idx on public.profiles (lower(email))
where email is not null;

-- Keep former players visible in historical game records without showing them as opponents.
drop policy if exists "active roster readable by signed-in users" on public.players;
create policy "roster readable for active players and game history" on public.players
for select to authenticated using (
  is_active
  or public.is_club_admin()
  or exists (
    select 1 from public.games g
    where g.voided_at is null
      and public.players.id in (g.white_player_id, g.black_player_id)
  )
);
