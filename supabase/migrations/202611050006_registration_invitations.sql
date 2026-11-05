-- Track whether the account invitation for an approved registration was sent.
alter table public.registration_requests
  add column if not exists invitation_sent_at timestamptz;

-- When an invited user accepts, automatically connect the new auth account to
-- the roster player created during registration approval. Match on the approved
-- email address rather than trusting user-editable signup metadata.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
declare
  approved_request public.registration_requests%rowtype;
  chosen_name text;
begin
  select * into approved_request
  from public.registration_requests
  where status = 'approved'
    and player_id is not null
    and lower(trim(email)) = lower(trim(new.email))
  order by reviewed_at desc nulls last, submitted_at desc
  limit 1;

  chosen_name := coalesce(
    nullif(trim(approved_request.full_name), ''),
    nullif(trim(new.raw_user_meta_data->>'display_name'), ''),
    split_part(coalesce(new.email, 'Player'), '@', 1)
  );

  insert into public.profiles (id, display_name, email, player_id)
  values (
    new.id,
    chosen_name,
    new.email,
    approved_request.player_id
  )
  on conflict (id) do update
    set email = excluded.email,
        player_id = coalesce(public.profiles.player_id, excluded.player_id),
        display_name = case
          when public.profiles.player_id is null then excluded.display_name
          else public.profiles.display_name
        end;

  return new;
end;
$$;
