create extension if not exists pg_cron with schema pg_catalog;

grant usage on schema cron to postgres;
grant all privileges on all tables in schema cron to postgres;

create index if not exists game_submissions_pending_expiry_idx
  on public.game_submissions (created_at)
  where status = 'pending';

create or replace function public.auto_approve_expired_game_submissions()
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  s public.game_submissions%rowtype;
  submitter_player uuid;
  opponent_user uuid;
  opponent_player uuid;
  new_game_id uuid;
  approved_count integer := 0;
begin
  for s in
    select *
    from public.game_submissions
    where status = 'pending'
      and created_at <= now() - interval '3 hours'
    order by created_at asc
    for update skip locked
  loop
    insert into public.games
      (white_player_id, black_player_id, result, played_at, source_submission_id, entered_by)
    values
      (s.white_player_id, s.black_player_id, s.result, s.played_at, s.id, s.submitted_by)
    on conflict (source_submission_id) do nothing
    returning id into new_game_id;

    if new_game_id is null then
      select id into new_game_id
      from public.games
      where source_submission_id = s.id;
    end if;

    update public.game_submissions
      set status = 'approved',
          reviewed_by = null,
          reviewed_at = now(),
          review_note = null
      where id = s.id;

    insert into public.audit_log (actor_user_id, action, entity_type, entity_id, details)
    values (
      null,
      'submission_auto_approved',
      'game_submission',
      s.id,
      jsonb_build_object(
        'game_id', new_game_id,
        'reason', 'No rejection within the three-hour review window',
        'submitted_at', s.created_at,
        'auto_approved_at', now()
      )
    );

    select player_id into submitter_player
    from public.profiles
    where id = s.submitted_by;

    opponent_player := case
      when submitter_player = s.white_player_id then s.black_player_id
      else s.white_player_id
    end;

    select id into opponent_user
    from public.profiles
    where player_id = opponent_player
    limit 1;

    insert into public.notifications (recipient_user_id, kind, message, submission_id)
    values (
      s.submitted_by,
      'submission_auto_approved',
      'Your game result was automatically approved after three hours without a rejection.',
      s.id
    );

    if opponent_user is not null and opponent_user <> s.submitted_by then
      insert into public.notifications (recipient_user_id, kind, message, submission_id)
      values (
        opponent_user,
        'game_auto_approved',
        'A submitted game involving you was automatically approved after three hours without a rejection.',
        s.id
      );
    end if;

    approved_count := approved_count + 1;
    new_game_id := null;
  end loop;

  if approved_count > 0 then
    perform public.recalculate_ratings();
  end if;

  return approved_count;
end;
$$;

revoke all on function public.auto_approve_expired_game_submissions() from public, anon, authenticated;
grant execute on function public.auto_approve_expired_game_submissions() to postgres, service_role;

select cron.unschedule(jobid)
from cron.job
where jobname = 'auto-approve-expired-game-submissions';

select cron.schedule(
  'auto-approve-expired-game-submissions',
  '* * * * *',
  'select public.auto_approve_expired_game_submissions();'
);
