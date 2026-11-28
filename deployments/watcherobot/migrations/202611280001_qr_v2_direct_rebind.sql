begin;

-- Unified v2 QR direct binding & atomic cross-account replacement.
-- Requires a device-generated 64-hex link_key (no server-side random fallback)
-- so the cloud binding and the physical ESP32 always share the exact same key.
drop function if exists public.bind_account_device(text, text);
create function public.bind_account_device(
  p_device_id text,
  p_link_key text
)
returns table(device_id text, binding_version text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
  v_version bigint;
begin
  if v_owner is null then
    raise exception 'account_session_changed' using errcode = '42501';
  end if;

  if p_device_id is null
     or p_device_id !~ '^WR(-[0-9A-F]{4}){4}$'
     or p_link_key is null
     or p_link_key !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_account_device' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(73141203);

  insert into account_devices_private.owner_epochs(owner_id)
  values (v_owner)
  on conflict do nothing;

  insert into account_devices_private.binding_events(owner_id, device_id, binding_version, reason)
  select b.owner_id, b.device_id, b.binding_version, 'replaced'
  from account_devices_private.bindings as b
  where b.owner_id = v_owner or b.device_id = p_device_id or b.link_key = p_link_key;

  update account_devices_private.owner_epochs as oe
  set epoch = oe.epoch + 1
  where oe.owner_id = v_owner
     or oe.owner_id in (
       select b.owner_id
       from account_devices_private.bindings as b
       where b.device_id = p_device_id or b.link_key = p_link_key
     );

  delete from account_devices_private.bindings as b
  where b.owner_id = v_owner or b.device_id = p_device_id or b.link_key = p_link_key;

  v_version := nextval('account_devices_private.binding_versions');

  insert into account_devices_private.bindings(owner_id, device_id, link_key, binding_version)
  values (v_owner, p_device_id, p_link_key, v_version);

  insert into account_devices_private.credential_history(device_id, binding_version, link_key)
  values (p_device_id, v_version, p_link_key);

  update account_devices_private.enrollment_roots
  set generation = v_version
  where account_devices_private.enrollment_roots.device_id = p_device_id;

  insert into account_devices_private.binding_events(owner_id, device_id, binding_version, reason)
  values (v_owner, p_device_id, v_version, 'paired');

  return query select p_device_id, v_version::text;
end;
$$;

create or replace function public.unlink_my_device(
  p_device_id text,
  p_binding_version text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
  v_version bigint;
  v_deleted_version bigint;
begin
  if v_owner is null then
    raise exception 'account_session_changed' using errcode = '42501';
  end if;

  if p_device_id is null
     or p_device_id !~ '^WR(-[0-9A-F]{4}){4}$'
     or p_binding_version is null
     or p_binding_version !~ '^[1-9][0-9]*$' then
    raise exception 'invalid_account_device' using errcode = '22023';
  end if;

  v_version := p_binding_version::bigint;

  perform pg_advisory_xact_lock(73141203);

  delete from account_devices_private.bindings as b
  where b.owner_id = v_owner
    and b.device_id = p_device_id
    and b.binding_version = v_version
  returning b.binding_version into v_deleted_version;

  if v_deleted_version is null then
    return false;
  end if;

  insert into account_devices_private.owner_epochs(owner_id, epoch)
  values (v_owner, 1)
  on conflict (owner_id) do update
    set epoch = account_devices_private.owner_epochs.epoch + 1;

  insert into account_devices_private.binding_events(owner_id, device_id, binding_version, reason)
  values (v_owner, p_device_id, v_deleted_version, 'unlinked');

  return true;
end;
$$;

revoke execute on function public.bind_account_device(text, text) from public, anon, authenticated;
revoke execute on function public.unlink_my_device(text, text) from public, anon, authenticated;
grant execute on function public.bind_account_device(text, text) to authenticated;
grant execute on function public.unlink_my_device(text, text) to authenticated;

notify pgrst, 'reload schema';

commit;
