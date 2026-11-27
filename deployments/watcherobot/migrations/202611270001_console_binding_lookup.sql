begin;

create view account_devices_private.binding_overview with (security_invoker = true) as
select device_id, owner_id, binding_version
from account_devices_private.bindings;

comment on view account_devices_private.binding_overview is
  'Current account bindings for Studio operators; does not expose connection credentials.';

create function account_devices_private.find_binding_by_mac(p_bluetooth_mac macaddr)
returns setof account_devices_private.binding_overview
language sql stable strict security invoker set search_path = ''
as $$
  -- Match device_identity_core.c: domain bytes, a zero byte, then six Bluetooth MAC bytes.
  with identity as (
    select upper(left(encode(sha256(
      convert_to('watcher-ble-device-id-v1','UTF8') || decode('00','hex') || macaddr_send(p_bluetooth_mac)
    ),'hex'),16)) as hex
  )
  select binding.*
  from account_devices_private.binding_overview binding, identity
  where binding.device_id = concat_ws('-', 'WR',
    substr(hex,1,4), substr(hex,5,4), substr(hex,9,4), substr(hex,13,4));
$$;

revoke all on account_devices_private.binding_overview from public, anon, authenticated;
revoke all on function account_devices_private.find_binding_by_mac(macaddr) from public, anon, authenticated;

commit;
