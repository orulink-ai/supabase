begin;

create table account_devices_private.provisioning_claims (
    ticket_hash bytea primary key,
    owner_id uuid not null references auth.users(id) on delete cascade,
    device_id text not null check (device_id ~ '^WR(-[0-9A-F]{4}){4}$'),
    expires_at timestamptz not null,
    link_key text check (link_key ~ '^[0-9a-f]{64}$'),
    committed boolean not null default false
);
create index provisioning_claims_expiry on account_devices_private.provisioning_claims (expires_at);
alter table account_devices_private.provisioning_claims enable row level security;
revoke all on account_devices_private.provisioning_claims from public, anon, authenticated;

create function public.prepare_account_device_claim(p_device_id text)
returns text
language plpgsql security definer set search_path = ''
as $$
declare
    owner uuid := auth.uid();
    ticket text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
begin
    if owner is null or p_device_id is null or p_device_id !~ '^WR(-[0-9A-F]{4}){4}$' then
        raise exception 'invalid_provisioning_claim' using errcode = '22023';
    end if;
    delete from account_devices_private.provisioning_claims where expires_at <= now();
    insert into account_devices_private.provisioning_claims (ticket_hash, owner_id, device_id, expires_at)
    values (sha256(convert_to(ticket, 'UTF8')), owner, p_device_id, now() + interval '2 minutes');
    return ticket;
end;
$$;

create function public.stage_account_device_claim(p_ticket text, p_device_id text, p_link_key text)
returns void
language plpgsql security definer set search_path = ''
as $$
begin
    if p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' or p_link_key is null or p_link_key !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid_provisioning_claim' using errcode = '22023';
    end if;
    update account_devices_private.provisioning_claims
    set link_key = p_link_key
    where ticket_hash = sha256(convert_to(p_ticket, 'UTF8')) and device_id = p_device_id
      and expires_at > now() and not committed and (link_key is null or link_key = p_link_key);
    if not found then
        raise exception 'invalid_provisioning_claim' using errcode = '22023';
    end if;
end;
$$;

create function public.commit_account_device_claim(p_ticket text)
returns boolean
language plpgsql security definer set search_path = ''
as $$
declare
    claim account_devices_private.provisioning_claims%rowtype;
begin
    if auth.uid() is null or p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid_provisioning_claim' using errcode = '22023';
    end if;
    select * into claim from account_devices_private.provisioning_claims
    where ticket_hash = sha256(convert_to(p_ticket, 'UTF8')) and owner_id = auth.uid() and expires_at > now()
    for update;
    if not found then
        raise exception 'invalid_provisioning_claim' using errcode = '22023';
    end if;
    if claim.committed then
        return true;
    end if;
    if claim.link_key is null then
        return false;
    end if;
    perform public.claim_account_device(claim.owner_id, claim.device_id, claim.link_key);
    update account_devices_private.provisioning_claims set committed = true, link_key = null
    where ticket_hash = claim.ticket_hash;
    return true;
end;
$$;

revoke execute on function public.prepare_account_device_claim(text) from public, anon, authenticated;
revoke execute on function public.stage_account_device_claim(text, text, text) from public, anon, authenticated;
revoke execute on function public.commit_account_device_claim(text) from public, anon, authenticated;
grant execute on function public.prepare_account_device_claim(text) to authenticated;
grant execute on function public.stage_account_device_claim(text, text, text) to anon;
grant execute on function public.commit_account_device_claim(text) to authenticated;

commit;
