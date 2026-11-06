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
    select 1 from pg_constraint
    where conname = 'registration_requests_skill_level_check'
      and conrelid = 'public.registration_requests'::regclass
  ) then
    alter table public.registration_requests
      add constraint registration_requests_skill_level_check
      check (skill_level in ('Beginner', 'Intermediate', 'Advanced', 'Expert'));
  end if;
end
$$;
