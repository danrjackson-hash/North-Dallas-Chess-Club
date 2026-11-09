alter table public.club_registration_secrets
  add column if not exists code_encrypted text;
