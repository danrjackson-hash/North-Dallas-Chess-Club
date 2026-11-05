-- Let an authenticated user determine whether they have set a password.
-- Invited users have an empty auth.users.encrypted_password until they choose one.
create or replace function public.current_user_has_password()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from auth.users
    where id = auth.uid()
      and coalesce(encrypted_password, '') <> ''
  );
$$;

revoke all on function public.current_user_has_password() from public;
revoke all on function public.current_user_has_password() from anon;
grant execute on function public.current_user_has_password() to authenticated;
