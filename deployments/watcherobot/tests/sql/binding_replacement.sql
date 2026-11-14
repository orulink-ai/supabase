-- Runs only in a disposable database, after the legacy and replacement migrations.
\set ON_ERROR_STOP on
create function pg_temp.assert_true(ok boolean, label text) returns void language plpgsql as $$
begin if ok is distinct from true then raise exception 'assertion failed: %', label; end if; end $$;
insert into auth.users(id) values ('00000000-0000-0000-0000-000000000001'),('00000000-0000-0000-0000-000000000002');
insert into account_devices_private.deployment values (true,'CN');
insert into account_devices_private.enrollment_roots(device_id,secret) values
('WR-0001-0000-0000-0000',repeat('11',32)),('WR-0002-0000-0000-0000',repeat('22',32));
insert into account_devices_private.enrollment_roots(device_id,secret) values('WR-0009-0000-0000-0000',repeat('99',32));
select binding_version::text as legacy_version from account_devices_private.bindings
 where device_id='WR-0009-0000-0000-0000' \gset
select public.account_device_status_v3('WR-0009-0000-0000-0000',:'legacy_version',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc') as legacy_status \gset
select pg_temp.assert_true((:'legacy_status'::jsonb)->>'state'='active','migration backfills existing credential history');
-- A migrated device proves the old credential using its privately enrolled root.
select public.bootstrap_account_device_v3('WR-0009-0000-0000-0000',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
 encode(extensions.hmac(convert_to('watcher-bootstrap-v3|CN|c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc|WR-0009-0000-0000-0000|'||repeat('99',32),'UTF8'),decode(repeat('99',32),'hex'),'sha256'),'hex')) as bootstrap \gset
select pg_temp.assert_true((:'bootstrap'::jsonb)->>'binding_version'=:'legacy_version','bootstrap preserves migrated version');
select pg_temp.assert_true(not (:'bootstrap'::jsonb ? 'link_key') and not (:'bootstrap'::jsonb ? 'owner_id'),'bootstrap keeps private credentials private');

delete from account_devices_private.bindings where device_id='WR-0009-0000-0000-0000';
select public.account_device_status_v3('WR-0009-0000-0000-0000',:'legacy_version',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc') as legacy_revoked \gset
select pg_temp.assert_true((:'legacy_revoked'::jsonb)->>'state'='revoked','legacy credential remains revocable after replacement');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',false);
select public.prepare_account_device_claim_v3('WR-0001-0000-0000-0000','CN') as ticket \gset
select pg_temp.assert_true(not public.commit_account_device_claim_v3(:'ticket'),'unstaged claim cannot replace');
select public.stage_account_device_claim_v3(:'ticket','WR-0001-0000-0000-0000',repeat('ab',32),
encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'ticket'||'|WR-0001-0000-0000-0000|'||repeat('ab',32),'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
select public.commit_account_device_claim_v3(:'ticket');
select pg_temp.assert_true((select count(*)=0 from account_devices_private.bindings),'activation failure cannot publish a binding');
select pg_temp.assert_true(not public.commit_account_device_claim_v3(:'ticket'),'App waits for durable device acknowledgement');
select public.account_device_claim_state_v3(:'ticket','WR-0001-0000-0000-0000') as receipt \gset
select pg_temp.assert_true((:'receipt'::jsonb)->>'state'='committed','server activation receipt');
select pg_temp.assert_true(not (:'receipt'::jsonb ? 'link_key'),'anonymous receipt never exposes key');
select public.ack_account_device_claim_v3(:'ticket','WR-0001-0000-0000-0000',
encode(extensions.hmac(convert_to('watcher-ack-v3|CN|'||:'ticket'||'|WR-0001-0000-0000-0000|'||repeat('ab',32)||'|'||((:'receipt'::jsonb)->>'binding_version'),'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
select pg_temp.assert_true(public.commit_account_device_claim_v3(:'ticket'),'acknowledged commit is idempotent');
select public.account_device_status_v3('WR-0001-0000-0000-0000',(:'receipt'::jsonb)->>'binding_version',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc') as live_status \gset
select pg_temp.assert_true((:'live_status'::jsonb)->>'state'='active','current hardware credential remains active');
select public.prepare_account_device_claim_v3('WR-0001-0000-0000-0000','CN') as racing_ticket \gset
select public.stage_account_device_claim_v3(:'racing_ticket','WR-0001-0000-0000-0000',repeat('de',32),
encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'racing_ticket'||'|WR-0001-0000-0000-0000|'||repeat('de',32),'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
select public.prepare_account_device_claim_v3('WR-0002-0000-0000-0000','CN') as ticket2 \gset
select pg_temp.assert_true(not public.commit_account_device_claim_v3(:'ticket2'),'failure preserves previous binding');
select pg_temp.assert_true((select device_id='WR-0001-0000-0000-0000' from account_devices_private.bindings),'old device preserved');
select public.stage_account_device_claim_v3(:'ticket2','WR-0002-0000-0000-0000',repeat('cd',32),
encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'ticket2'||'|WR-0002-0000-0000-0000|'||repeat('cd',32),'UTF8'),decode(repeat('22',32),'hex'),'sha256'),'hex'));
select public.commit_account_device_claim_v3(:'ticket2');
select pg_temp.assert_true((select device_id='WR-0001-0000-0000-0000' from account_devices_private.bindings),'old binding survives until new device durable activation');
select public.account_device_claim_state_v3(:'ticket2','WR-0002-0000-0000-0000') as receipt2 \gset
select public.ack_account_device_claim_v3(:'ticket2','WR-0002-0000-0000-0000',
encode(extensions.hmac(convert_to('watcher-ack-v3|CN|'||:'ticket2'||'|WR-0002-0000-0000-0000|'||repeat('cd',32)||'|'||((:'receipt2'::jsonb)->>'binding_version'),'UTF8'),decode(repeat('22',32),'hex'),'sha256'),'hex'));
select pg_temp.assert_true((select count(*)=1 and min(device_id)='WR-0002-0000-0000-0000' from account_devices_private.bindings),'new device replaces old');
select public.account_device_status_v3('WR-0001-0000-0000-0000',(:'receipt'::jsonb)->>'binding_version',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc') as old_status \gset
select pg_temp.assert_true((:'old_status'::jsonb)->>'state'='revoked','old hardware learns revocation after internet returns');
select pg_temp.assert_true((:'old_status'::jsonb)->>'proof'=encode(extensions.hmac(convert_to(
 'watcher-revoked-v3|CN|c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc|WR-0001-0000-0000-0000|'||repeat('ab',32)||'|'||((:'receipt'::jsonb)->>'binding_version'),
 'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'),'revocation is hardware-signed and nonce-bound');
select pg_temp.assert_true(not (:'old_status'::jsonb ? 'link_key'),'status never exposes old credential');
select set_config('test.old_ticket',:'ticket',false);
select set_config('test.racing_ticket',:'racing_ticket',false);
do $$ begin
  begin perform public.commit_account_device_claim_v3(current_setting('test.old_ticket'));
    raise exception 'superseded idempotent request accepted';
  exception when invalid_parameter_value then null; end;
  begin perform public.commit_account_device_claim_v3(current_setting('test.racing_ticket'));
    raise exception 'racing owner request overwrote newer binding';
  exception when invalid_parameter_value then null; end;
end $$;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000002',false);
select public.prepare_account_device_claim_v3('WR-0002-0000-0000-0000','CN') as ticket3 \gset
select public.stage_account_device_claim_v3(:'ticket3','WR-0002-0000-0000-0000',repeat('ef',32),
encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'ticket3'||'|WR-0002-0000-0000-0000|'||repeat('ef',32),'UTF8'),decode(repeat('22',32),'hex'),'sha256'),'hex'));
select public.commit_account_device_claim_v3(:'ticket3');
select public.account_device_claim_state_v3(:'ticket3','WR-0002-0000-0000-0000') as receipt3 \gset
select public.ack_account_device_claim_v3(:'ticket3','WR-0002-0000-0000-0000',
encode(extensions.hmac(convert_to('watcher-ack-v3|CN|'||:'ticket3'||'|WR-0002-0000-0000-0000|'||repeat('ef',32)||'|'||((:'receipt3'::jsonb)->>'binding_version'),'UTF8'),decode(repeat('22',32),'hex'),'sha256'),'hex'));
select pg_temp.assert_true((select count(*)=1 and min(owner_id::text)='00000000-0000-0000-0000-000000000002' from account_devices_private.bindings),'physical re-pair replaces owner');
select pg_temp.assert_true(not has_function_privilege('authenticated','public.claim_account_device(uuid,text,text)','EXECUTE'),'old direct path disabled');
select pg_temp.assert_true(not has_function_privilege('anon','public.stage_account_device_claim(text,text,text)','EXECUTE'),'old bearer stage disabled');
select pg_temp.assert_true(not has_table_privilege('authenticated','account_devices_private.enrollment_roots','SELECT'),'hardware verifier private');
do $$ begin
  begin perform public.stage_account_device_claim_v3(repeat('0',64),'WR-0002-0000-0000-0000',repeat('ef',32),repeat('00',32));
    raise exception 'forged proof accepted';
  exception when invalid_parameter_value then null; end;
  begin perform public.prepare_account_device_claim_v3('WR-0003-0000-0000-0000','CN');
    raise exception 'unregistered hardware accepted';
  exception when invalid_parameter_value then null; end;
  begin perform public.prepare_account_device_claim_v3('WR-0001-0000-0000-0000','GLOBAL');
    raise exception 'cross-region ticket accepted';
  exception when invalid_parameter_value then null; end;
end $$;
select 'binding replacement assertions passed';
delete from auth.users where id='00000000-0000-0000-0000-000000000001';
select public.account_device_status_v3('WR-0001-0000-0000-0000',(:'receipt'::jsonb)->>'binding_version',
 'c3a3c3a3cccccccccccccccccccccccccccccccccccccccccccccccccccccccc') as deleted_owner_status \gset
select pg_temp.assert_true((:'deleted_owner_status'::jsonb)->>'state'='revoked','account deletion preserves device revocation proof');
