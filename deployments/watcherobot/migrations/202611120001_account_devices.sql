begin;

create schema account_devices_private;
revoke all on schema account_devices_private from public, anon, authenticated;

create table account_devices_private.bindings (
    owner_id uuid not null references auth.users(id) on delete cascade,
    device_id text not null,
    link_key text not null unique,
    primary key (owner_id, device_id),
    check (device_id ~ '^WR(-[0-9A-F]{4}){4}$'),
    check (link_key ~ '^[0-9a-f]{64}$')
);
alter table account_devices_private.bindings enable row level security;
revoke all on account_devices_private.bindings from public, anon, authenticated;

create function public.claim_account_device(p_owner_id uuid, p_device_id text, p_link_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if auth.uid() is null or auth.uid() is distinct from p_owner_id then
        raise exception 'account_session_changed' using errcode = '42501';
    end if;

    if p_device_id is null or p_device_id !~ '^WR(-[0-9A-F]{4}){4}$'
        or p_link_key is null or p_link_key !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid_account_device' using errcode = '22023';
    end if;

    insert into account_devices_private.bindings (owner_id, device_id, link_key)
    values (p_owner_id, p_device_id, p_link_key)
    on conflict (owner_id, device_id) do update
    set link_key = excluded.link_key;
exception
    when unique_violation then
        raise exception 'device_key_already_claimed' using errcode = '23505';
end;
$$;

create function public.list_account_devices(p_owner_id uuid)
returns table (device_id text)
language plpgsql stable
security definer
set search_path = ''
as $$
begin
    if auth.uid() is null or auth.uid() is distinct from p_owner_id then
        raise exception 'account_session_changed' using errcode = '42501';
    end if;

    return query select binding.device_id
    from account_devices_private.bindings as binding
    where binding.owner_id = p_owner_id
    order by binding.device_id;
end;
$$;

create function public.get_account_device_link(p_owner_id uuid, p_device_id text)
returns text
language plpgsql stable
security definer
set search_path = ''
as $$
begin
    if auth.uid() is null or auth.uid() is distinct from p_owner_id then
        raise exception 'account_session_changed' using errcode = '42501';
    end if;

    return (
        select binding.link_key
        from account_devices_private.bindings as binding
        where binding.owner_id = p_owner_id and binding.device_id = p_device_id
    );
end;
$$;

revoke execute on function public.claim_account_device(uuid, text, text) from public, anon;
revoke execute on function public.list_account_devices(uuid) from public, anon;
revoke execute on function public.get_account_device_link(uuid, text) from public, anon;

grant execute on function public.claim_account_device(uuid, text, text) to authenticated;
grant execute on function public.list_account_devices(uuid) to authenticated;
grant execute on function public.get_account_device_link(uuid, text) to authenticated;

commit;
