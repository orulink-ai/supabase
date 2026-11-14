-- Follow-up contract: run after binding_replacement.sql in the disposable DB.
\set ON_ERROR_STOP on
create function pg_temp.assert_true(ok boolean, label text) returns void language plpgsql as $$
begin if ok is distinct from true then raise exception 'assertion failed: %', label; end if; end $$;
insert into auth.users(id) values
 ('00000000-0000-0000-0000-000000000010'),('00000000-0000-0000-0000-000000000011');
insert into account_devices_private.enrollment_roots(device_id,secret) values
 ('WR-0010-0000-0000-0000',repeat('10',32)),('WR-0011-0000-0000-0000',repeat('11',32));
insert into account_devices_private.bindings(owner_id,device_id,link_key)
 values('00000000-0000-0000-0000-000000000010','WR-0010-0000-0000-0000',repeat('aa',32));
insert into account_devices_private.credential_history(device_id,binding_version,link_key)
 select device_id,binding_version,link_key from account_devices_private.bindings where device_id='WR-0010-0000-0000-0000';
select binding_version::text as previous_version from account_devices_private.bindings
 where device_id='WR-0010-0000-0000-0000' \gset
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000011',false);
select public.prepare_account_device_claim_v3('WR-0010-0000-0000-0000','CN') as race_ticket \gset
select public.stage_account_device_claim_v3(:'race_ticket','WR-0010-0000-0000-0000',repeat('bb',32),
 encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'race_ticket'||'|WR-0010-0000-0000-0000|'||repeat('bb',32),
 'UTF8'),decode(repeat('10',32),'hex'),'sha256'),'hex'));
select public.commit_account_device_claim_v3(:'race_ticket');
select public.prepare_account_device_claim_v3('WR-0011-0000-0000-0000','CN') as winning_ticket \gset
select public.stage_account_device_claim_v3(:'winning_ticket','WR-0011-0000-0000-0000',repeat('cc',32),
 encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'winning_ticket'||'|WR-0011-0000-0000-0000|'||repeat('cc',32),
 'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
select public.commit_account_device_claim_v3(:'winning_ticket');
select public.account_device_claim_state_v3(:'winning_ticket','WR-0011-0000-0000-0000') as winner \gset
select public.ack_account_device_claim_v3(:'winning_ticket','WR-0011-0000-0000-0000',
 encode(extensions.hmac(convert_to('watcher-ack-v3|CN|'||:'winning_ticket'||'|WR-0011-0000-0000-0000|'||repeat('cc',32)||'|'||(:'winner'::jsonb->>'binding_version'),
 'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
select public.account_device_claim_state_v3(:'race_ticket','WR-0010-0000-0000-0000') as aborted \gset
select pg_temp.assert_true(:'aborted'::jsonb->>'state'='aborted','owner epoch race has authenticated abort terminal');
select pg_temp.assert_true(:'aborted'::jsonb->>'proof'=encode(extensions.hmac(convert_to(
 'watcher-abort-v3|CN|'||:'race_ticket'||'|WR-0010-0000-0000-0000|'||repeat('bb',32)||'|'||(:'aborted'::jsonb->>'binding_version'),
 'UTF8'),decode(repeat('10',32),'hex'),'sha256'),'hex'),'abort proof binds ticket candidate and version');
select pg_temp.assert_true((select link_key=repeat('aa',32) and binding_version::text=:'previous_version'
 from account_devices_private.bindings where device_id='WR-0010-0000-0000-0000'),'failed replacement preserves previous cloud binding');
select public.account_device_claim_state_v3(:'winning_ticket','WR-0011-0000-0000-0000') as ack_lost \gset
select pg_temp.assert_true(:'ack_lost'::jsonb->>'state'='active','lost ACK response remains distinguishable from abort');
delete from account_devices_private.bindings where device_id='WR-0011-0000-0000-0000';
select public.account_device_claim_state_v3(:'winning_ticket','WR-0011-0000-0000-0000') as revoked_claim \gset
select pg_temp.assert_true(:'revoked_claim'::jsonb->>'state'='revoked','previously acknowledged claim must revoke rather than abort');
select pg_temp.assert_true(:'revoked_claim'::jsonb->>'proof'=encode(extensions.hmac(convert_to(
 'watcher-revoked-v3|CN|'||:'winning_ticket'||'|WR-0011-0000-0000-0000|'||repeat('cc',32)||'|'||(:'winner'::jsonb->>'binding_version'),
 'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'),'acknowledged terminal revocation is signed');
delete from account_devices_private.bindings where device_id='WR-0010-0000-0000-0000';
select public.bootstrap_account_device_v3('WR-0010-0000-0000-0000',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
 encode(extensions.hmac(convert_to('watcher-bootstrap-v3|CN|c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc|WR-0010-0000-0000-0000|'||repeat('aa',32),
 'UTF8'),decode(repeat('10',32),'hex'),'sha256'),'hex')) as old_bootstrap \gset
select pg_temp.assert_true(:'old_bootstrap'::jsonb->>'state'='revoked','first bootstrap after cloud replacement revokes historical key');
select pg_temp.assert_true(:'old_bootstrap'::jsonb->>'binding_version'=:'previous_version','historical bootstrap resolves original version');
select pg_temp.assert_true(:'old_bootstrap'::jsonb->>'proof'=encode(extensions.hmac(convert_to(
 'watcher-revoked-v3|CN|c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc|WR-0010-0000-0000-0000|'||repeat('aa',32)||'|'||:'previous_version',
 'UTF8'),decode(repeat('10',32),'hex'),'sha256'),'hex'),'historical bootstrap decision is challenge bound');
select pg_temp.assert_true(not (:'old_bootstrap'::jsonb ? 'link_key') and not (:'old_bootstrap'::jsonb ? 'owner_id'),
 'historical bootstrap exposes neither key nor owner');
do $$ begin
  begin
    perform public.bootstrap_account_device_v3('WR-0010-0000-0000-0000',
      'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc',repeat('00',32));
    raise exception 'forged historical proof accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.bootstrap_account_device_v3('WR-0010-0000-0000-0000',
      'b3a3b3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc',repeat('00',32));
    raise exception 'foreign regional challenge accepted';
  exception when invalid_parameter_value then null; end;
end $$;
select pg_temp.assert_true(has_function_privilege('anon','public.bootstrap_account_device_v3(text,text,text)','EXECUTE')
 and not has_function_privilege('authenticated','public.bootstrap_account_device_v3(text,text,text)','EXECUTE'),
 'replacement functions preserve least privilege grants');
select 'claim recovery assertions passed';
