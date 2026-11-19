-- Restrict result review to the opposing player; administrators manage games separately.
create or replace function public.review_game_submission(
  p_submission_id uuid, p_approve boolean, p_note text default null
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
  select * into s from public.game_submissions where id = p_submission_id for update;
  if not found then raise exception 'Submission not found'; end if;
  if s.status not in ('pending', 'needs_review') then raise exception 'This submission has already been reviewed'; end if;
  if auth.uid() is null or auth.uid() = s.submitted_by then raise exception 'You cannot review your own submission'; end if;

  select player_id into reviewer_player from public.profiles where id = auth.uid();
  if reviewer_player is null or reviewer_player not in (s.white_player_id, s.black_player_id) then
    raise exception 'Only the opposing player can review this result';
  end if;

  if p_approve then
    insert into public.games (white_player_id, black_player_id, result, played_at, source_submission_id, entered_by)
    values (s.white_player_id, s.black_player_id, s.result, s.played_at, s.id, s.submitted_by)
    returning id into new_game_id;
    update public.game_submissions set status='approved', reviewed_by=auth.uid(), reviewed_at=now(), review_note=null where id=s.id;
    perform public.recalculate_ratings();
    insert into public.audit_log(actor_user_id,action,entity_type,entity_id,details)
    values(auth.uid(),'submission_approved','game_submission',s.id,jsonb_build_object('game_id',new_game_id));
  else
    update public.game_submissions set status='rejected', reviewed_by=auth.uid(), reviewed_at=now(),
      review_note=left(coalesce(p_note,'Result rejected'),1000) where id=s.id;
    insert into public.audit_log(actor_user_id,action,entity_type,entity_id,details)
    values(auth.uid(),'submission_rejected','game_submission',s.id,
      jsonb_build_object('note',left(coalesce(p_note,'Result rejected'),1000)));
  end if;

  select player_id into submitter_player from public.profiles where id=s.submitted_by;
  select id into opponent_user from public.profiles
  where player_id=case when submitter_player=s.white_player_id then s.black_player_id else s.white_player_id end;
  insert into public.notifications(recipient_user_id,kind,message,submission_id)
  values(s.submitted_by,case when p_approve then 'submission_approved' else 'submission_rejected' end,
    case when p_approve then 'Your game result was approved.'
      else 'Your game result was rejected: '||coalesce(p_note,'Please check the result.') end,s.id);
  if opponent_user is not null and opponent_user<>auth.uid() then
    insert into public.notifications(recipient_user_id,kind,message,submission_id)
    values(opponent_user,case when p_approve then 'game_approved' else 'game_rejected' end,
      case when p_approve then 'A submitted game involving you was approved.'
        else 'A submitted game involving you was rejected.' end,s.id);
  end if;
end;
$$;
revoke all on function public.review_game_submission(uuid,boolean,text) from public,anon;
grant execute on function public.review_game_submission(uuid,boolean,text) to authenticated;

-- A manual rating edit replaces the previous baseline adjustment rather than stacking it.
create or replace function public.admin_set_player_rating(p_player_id uuid,p_new_rating integer)
returns void language plpgsql security definer set search_path=public
as $$
declare player_row public.players%rowtype; new_adjustment integer;
begin
  if auth.uid() is null or not public.is_club_admin() then raise exception 'Only a club admin can change player ratings'; end if;
  if p_new_rating is null or p_new_rating<100 or p_new_rating>4000 then raise exception 'Rating must be a whole number between 100 and 4000'; end if;
  select * into player_row from public.players where id=p_player_id for update;
  if not found then raise exception 'Player not found'; end if;
  new_adjustment:=p_new_rating-player_row.starting_rating;
  update public.players set rating_adjustment=new_adjustment where id=p_player_id;
  perform public.recalculate_ratings();
  insert into public.audit_log(actor_user_id,action,entity_type,entity_id,details)
  values(auth.uid(),'player_rating_baseline_set','player',p_player_id,
    jsonb_build_object('player_name',player_row.display_name,'previous_current_rating',player_row.current_rating,
      'previous_rating_adjustment',player_row.rating_adjustment,'new_baseline_rating',p_new_rating,
      'new_rating_adjustment',new_adjustment));
end;
$$;
revoke all on function public.admin_set_player_rating(uuid,integer) from public,anon;
grant execute on function public.admin_set_player_rating(uuid,integer) to authenticated;

-- Cancel games by voiding, preserving the record and recalculating the rating ledger.
create or replace function public.admin_void_game(p_game_id uuid,p_reason text)
returns void language plpgsql security definer set search_path=public
as $$
declare game_row public.games%rowtype; clean_reason text;
begin
  if auth.uid() is null or not public.is_club_admin() then raise exception 'Only a club admin can cancel a game'; end if;
  clean_reason:=left(trim(coalesce(p_reason,'')),500);
  if clean_reason='' then raise exception 'Please provide a reason for canceling this game'; end if;
  select * into game_row from public.games where id=p_game_id for update;
  if not found then raise exception 'Game not found'; end if;
  if game_row.voided_at is not null then raise exception 'This game has already been canceled'; end if;
  update public.games set voided_at=now(),voided_by=auth.uid(),void_reason=clean_reason where id=p_game_id;
  perform public.recalculate_ratings();
  insert into public.audit_log(actor_user_id,action,entity_type,entity_id,details)
  values(auth.uid(),'game_voided','game',p_game_id,
    jsonb_build_object('white_player_id',game_row.white_player_id,'black_player_id',game_row.black_player_id,
      'result',game_row.result,'played_at',game_row.played_at,'reason',clean_reason));
end;
$$;
revoke all on function public.admin_void_game(uuid,text) from public,anon;
grant execute on function public.admin_void_game(uuid,text) to authenticated;

-- Restore Daniel's confirmed 1,800 pre-game baseline; preserve all official games.
do $$
declare affected integer;
begin
  update public.players set rating_adjustment=400
  where display_name='Daniel Jackson' and starting_rating=1400 and rating_adjustment=434;
  get diagnostics affected=row_count;
  if affected<>1 then raise exception 'Expected exactly one Daniel Jackson rating row with adjustment 434; found %',affected; end if;
end;
$$;
select public.recalculate_ratings();
insert into public.audit_log(actor_user_id,action,entity_type,entity_id,details)
select auth.uid(),'player_rating_baseline_corrected','player',p.id,
  jsonb_build_object('previous_adjustment',434,'new_adjustment',400,'baseline_rating',1800,
    'reason','Corrected accumulated test-time manual adjustments; official games retained')
from public.players p where p.display_name='Daniel Jackson' and p.starting_rating=1400 and p.rating_adjustment=400;
