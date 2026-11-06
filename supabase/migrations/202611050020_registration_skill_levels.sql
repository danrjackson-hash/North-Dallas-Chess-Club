-- Add a self-selected starting skill level to registration requests.
-- Existing requests are backfilled as Intermediate to preserve the former 1400 default.
alter table public.registration_requests
  add column if not exists skill_level text;

update public.registration_requests
set skill_level = 'Intermediate'
where skill_level is null;

alter table public.registration_requests
  alter column skill_level set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'registration_requests_skill_level_check'
      and conrelid = 'public.registration_requests'::regclass
  ) then
    alter table public.registration_requests
      add constraint registration_requests_skill_level_check
      check (skill_level in ('Beginner', 'Intermediate', 'Advanced', 'Expert'));
  end if;
end
$$;

-- The existing review_registration_request RPC remains unchanged. When it
-- approves a request and assigns its new player_id, this trigger applies the
-- selected starting rating in the same transaction.
create or replace function public.apply_registration_skill_level()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  initial_rating integer;
begin
  if old.status = 'pending'
     and new.status = 'approved'
     and new.player_id is not null then
    initial_rating := case new.skill_level
      when 'Beginner' then 1000
      when 'Intermediate' then 1400
      when 'Advanced' then 1800
      when 'Expert' then 2200
      else 1400
    end;

    update public.players
    set starting_rating = initial_rating,
        current_rating = initial_rating
    where id = new.player_id;
  end if;

  return new;
end;
$$;

drop trigger if exists apply_registration_skill_level
  on public.registration_requests;

create trigger apply_registration_skill_level
after update of status on public.registration_requests
for each row
execute function public.apply_registration_skill_level();

revoke all on function public.apply_registration_skill_level() from public, anon, authenticated;
