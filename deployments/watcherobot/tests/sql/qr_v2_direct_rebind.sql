-- Runs in a disposable database after all migrations.
\set ON_ERROR_STOP on

create function pg_temp.assert_eq(actual text, expected text, label text) returns void language plpgsql as $$
begin
  if actual is distinct from expected then
    raise exception 'assertion failed (%): expected %, got %', label, expected, actual;
  end if;
end $$;

insert into auth.users(id) values
  ('00000000-0000-0000-0000-0000000000a1'),
  ('00000000-0000-0000-0000-0000000000a2')
on conflict do nothing;

-- 1. Reject null or invalid link_key (no silent server-side key generation).
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000a1', false);
do $$ begin
  begin
    perform * from public.bind_account_device('WR-AAAA-BBBB-CCCC-0001', null);
    raise exception 'null link_key was unexpectedly accepted';
  exception when invalid_parameter_value then null; end;

  begin
    perform * from public.bind_account_device('WR-AAAA-BBBB-CCCC-0001', '');
    raise exception 'empty link_key was unexpectedly accepted';
  exception when invalid_parameter_value then null; end;
end $$;

-- 2. Bind device A to account A1 with a device-generated 64-hex v2 key.
select device_id as bound_id, binding_version as bound_ver
from public.bind_account_device('WR-AAAA-BBBB-CCCC-0001', repeat('a1', 32)) \gset
select pg_temp.assert_eq(:'bound_id', 'WR-AAAA-BBBB-CCCC-0001', 'first v2 bind succeeds');
select pg_temp.assert_eq(
  public.get_account_device_link('00000000-0000-0000-0000-0000000000a1', 'WR-AAAA-BBBB-CCCC-0001'),
  repeat('a1', 32),
  'desktop reads exact device-generated link_key'
);

-- 3. Same account switches from device A to device B: A is released atomically.
select device_id as bound_id2, binding_version as bound_ver2
from public.bind_account_device('WR-AAAA-BBBB-CCCC-0002', repeat('a2', 32)) \gset
select pg_temp.assert_eq(:'bound_id2', 'WR-AAAA-BBBB-CCCC-0002', 'same-account switch binds B');
select pg_temp.assert_eq(
  (select count(*)::text from account_devices_private.bindings where owner_id = '00000000-0000-0000-0000-0000000000a1'),
  '1',
  'account A1 still owns exactly one device'
);
select pg_temp.assert_eq(
  (select count(*)::text from account_devices_private.bindings where device_id = 'WR-AAAA-BBBB-CCCC-0001'),
  '0',
  'old device A is released'
);

-- 4. Cross-account direct replacement: account A2 scans device B without A1 unlinking first.
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000a2', false);
select device_id as bound_id3, binding_version as bound_ver3
from public.bind_account_device('WR-AAAA-BBBB-CCCC-0002', repeat('b2', 32)) \gset
select pg_temp.assert_eq(:'bound_id3', 'WR-AAAA-BBBB-CCCC-0002', 'cross-account direct replace binds B to A2');
select pg_temp.assert_eq(
  (select count(*)::text from account_devices_private.bindings where owner_id = '00000000-0000-0000-0000-0000000000a1'),
  '0',
  'previous owner A1 is automatically unbound'
);
select pg_temp.assert_eq(
  public.get_account_device_link('00000000-0000-0000-0000-0000000000a2', 'WR-AAAA-BBBB-CCCC-0002'),
  repeat('b2', 32),
  'new owner A2 receives rotated link_key'
);

-- 5. Unlink by current owner succeeds and clears binding.
select pg_temp.assert_eq(
  public.unlink_my_device('WR-AAAA-BBBB-CCCC-0002', :'bound_ver3')::text,
  'true',
  'unlink_my_device removes active binding'
);
select pg_temp.assert_eq(
  (select count(*)::text from account_devices_private.bindings where device_id = 'WR-AAAA-BBBB-CCCC-0002'),
  '0',
  'binding removed after unlink'
);
