-- The registration PIN is now rotated only through the authenticated Edge Function.
-- Disable the legacy RPC, which stores an unkeyed hash and is no longer used.
revoke all on function public.admin_set_club_registration_code(text) from public, anon, authenticated;