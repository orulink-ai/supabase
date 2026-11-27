-- The device ID below is the ESP32 firmware hash of Bluetooth MAC 02:12:34:56:78:9A.
begin;
insert into auth.users(id) values ('00000000-0000-4000-8000-000000000088');
insert into account_devices_private.bindings(owner_id,device_id,link_key)
values ('00000000-0000-4000-8000-000000000088','WR-5C46-B7F3-1F29-B470',repeat('88',32));

do $test$
begin
  if (select count(*) from account_devices_private.find_binding_by_mac('02:12:34:56:78:9a')
      where owner_id = '00000000-0000-4000-8000-000000000088'
        and binding_version > 0) <> 1 then
    raise exception 'MAC did not resolve to its existing owner';
  end if;
  if exists(select from account_devices_private.find_binding_by_mac('02:12:34:56:78:9b')) then
    raise exception 'unbound MAC returned a binding';
  end if;
  if has_table_privilege('anon','account_devices_private.binding_overview','SELECT')
    or has_table_privilege('authenticated','account_devices_private.binding_overview','SELECT')
    or has_function_privilege('anon','account_devices_private.find_binding_by_mac(macaddr)','EXECUTE')
    or has_function_privilege('authenticated','account_devices_private.find_binding_by_mac(macaddr)','EXECUTE') then
    raise exception 'management metadata is visible to product clients';
  end if;
  if (select array_agg(column_name::text order by ordinal_position) from information_schema.columns
      where table_schema='account_devices_private' and table_name='binding_overview')
      is distinct from array['device_id','owner_id','binding_version'] then
    raise exception 'binding view exposes unexpected columns';
  end if;
end
$test$;
rollback;
