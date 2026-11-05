-- Let an authenticated user check only whether their own Supabase Auth account
-- has a password credential. This supports prompting invited players to set one.
create or replace function public.current_user_has_password()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (
      select nullif(u.encrypted_password, '') is not null
      from auth.users as u
      where u.id = (select auth.uid())
    ),
    false
  );
$$;

revoke all on function public.current_user_has_password() from public, anon;
grant execute on function public.current_user_has_password() to authenticated;
