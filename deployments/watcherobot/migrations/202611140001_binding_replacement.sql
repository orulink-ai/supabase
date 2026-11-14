begin;

-- Refuse ambiguous legacy data. Resolve conflicts explicitly before migrating.
do $$ begin
  if exists(select 1 from account_devices_private.bindings group by owner_id having count(*) > 1)
     or exists(select 1 from account_devices_private.bindings group by device_id having count(*) > 1) then
    raise exception 'legacy_binding_conflicts_require_review';
  end if;
end $$;
create sequence account_devices_private.binding_versions;
alter table account_devices_private.bindings
  add column binding_version bigint not null default nextval('account_devices_private.binding_versions'),
  add constraint bindings_one_owner unique(owner_id),
  add constraint bindings_one_device unique(device_id);

create table account_devices_private.deployment (
  singleton boolean primary key default true check(singleton),
  region text not null check(region in ('CN','GLOBAL'))
);
-- No owner reference: deleting an account must not make its old device
-- credential impossible to revoke. This material is never exposed by RPC.
create table account_devices_private.credential_history (
  device_id text not null check(device_id ~ '^WR(-[0-9A-F]{4}){4}$'),
  binding_version bigint not null,
  link_key text not null check(link_key ~ '^[0-9a-f]{64}$'),
  primary key(device_id,binding_version)
);
insert into account_devices_private.credential_history(device_id,binding_version,link_key)
  select device_id,binding_version,link_key from account_devices_private.bindings;
-- Factory/admin enrolled hardware verifiers; never populated from a public claim.
-- Each region receives a different device-derived verifier, not a global secret.
create table account_devices_private.enrollment_roots (
  device_id text primary key check(device_id ~ '^WR(-[0-9A-F]{4}){4}$'),
  secret text not null check(secret ~ '^[0-9a-f]{64}$'),
  generation bigint not null default 0 check(generation >= 0)
);
create table account_devices_private.owner_epochs (
  owner_id uuid primary key references auth.users(id) on delete cascade,
  epoch bigint not null default 0
);
create table account_devices_private.claims_v3 (
  ticket_hash bytea primary key,
  -- Retain only device revocation material after deleting an account identity.
  owner_id uuid references auth.users(id) on delete set null,
  device_id text not null references account_devices_private.enrollment_roots(device_id),
  region text not null,
  owner_epoch bigint not null,
  device_epoch bigint not null,
  expires_at timestamptz not null,
  link_key text check(link_key ~ '^[0-9a-f]{64}$'),
  binding_version bigint,
  acknowledged boolean not null default false
);
create table account_devices_private.binding_events (
  event_id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),
  owner_id uuid not null,
  device_id text not null,
  binding_version bigint not null,
  reason text not null
);
alter table account_devices_private.deployment enable row level security;
alter table account_devices_private.credential_history enable row level security;
alter table account_devices_private.enrollment_roots enable row level security;
alter table account_devices_private.owner_epochs enable row level security;
alter table account_devices_private.claims_v3 enable row level security;
alter table account_devices_private.binding_events enable row level security;
revoke all on all tables in schema account_devices_private from public,anon,authenticated;
revoke all on all sequences in schema account_devices_private from public,anon,authenticated;

create function public.prepare_account_device_claim_v3(p_device_id text,p_region text)
returns text language plpgsql security definer set search_path='' as $$
declare
  ticket text := (case when p_region='CN' then 'c3a3c3a3' else 'b3a3b3a3' end) ||
    left(replace(gen_random_uuid()::text||gen_random_uuid()::text,'-',''),56);
  owner uuid := auth.uid();
  device_epoch bigint;
  owner_epoch bigint;
begin
  if owner is null or not exists(select 1 from account_devices_private.deployment where region=p_region) then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  select generation into device_epoch from account_devices_private.enrollment_roots where device_id=p_device_id;
  if not found then raise exception 'hardware_not_enrolled' using errcode='22023'; end if;
  insert into account_devices_private.owner_epochs(owner_id) values(owner) on conflict do nothing;
  select epoch into owner_epoch from account_devices_private.owner_epochs where owner_id=owner;
  insert into account_devices_private.claims_v3(ticket_hash,owner_id,device_id,region,owner_epoch,device_epoch,expires_at)
  values(sha256(convert_to(ticket,'UTF8')),owner,p_device_id,p_region,owner_epoch,device_epoch,now()+interval '2 minutes');
  return ticket;
end $$;

create function public.stage_account_device_claim_v3(p_ticket text,p_device_id text,p_link_key text,p_proof text)
returns void language plpgsql security definer set search_path='' as $$
declare claim account_devices_private.claims_v3%rowtype; root text; expected text;
begin
  if p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' or p_link_key is null or p_link_key !~ '^[0-9a-f]{64}$'
     or p_proof is null or p_proof !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  select * into claim from account_devices_private.claims_v3
  where ticket_hash=sha256(convert_to(p_ticket,'UTF8')) and device_id=p_device_id and expires_at>now() for update;
  if not found or claim.binding_version is not null or (claim.link_key is not null and claim.link_key<>p_link_key) then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  select secret into root from account_devices_private.enrollment_roots where device_id=p_device_id and generation=claim.device_epoch;
  expected := encode(extensions.hmac(convert_to('watcher-claim-v3|'||claim.region||'|'||p_ticket||'|'||p_device_id||'|'||p_link_key,'UTF8'),decode(root,'hex'),'sha256'),'hex');
  if root is null or expected is distinct from p_proof or exists(
    select 1 from account_devices_private.bindings where device_id=p_device_id and link_key=p_link_key
  ) then raise exception 'invalid_device_claim' using errcode='22023'; end if;
  update account_devices_private.claims_v3 set link_key=p_link_key where ticket_hash=claim.ticket_hash;
end $$;

create function public.commit_account_device_claim_v3(p_ticket text)
returns boolean language plpgsql security definer set search_path='' as $$
declare claim account_devices_private.claims_v3%rowtype; version bigint;
begin
  if auth.uid() is null or p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  -- Serialize replacements, including owner/device swaps, in one lock order.
  perform pg_advisory_xact_lock(73141203);
  select * into claim from account_devices_private.claims_v3
  where ticket_hash=sha256(convert_to(p_ticket,'UTF8')) and owner_id=auth.uid() for update;
  if not found then raise exception 'invalid_device_claim' using errcode='22023'; end if;
  if claim.acknowledged then
    if not exists(select 1 from account_devices_private.bindings where owner_id=claim.owner_id
                  and device_id=claim.device_id and binding_version=claim.binding_version) then
      raise exception 'claim_superseded' using errcode='22023';
    end if;
    return true;
  end if;
  if claim.binding_version is null and claim.expires_at<=now() then
    raise exception 'claim_expired' using errcode='22023';
  end if;
  if claim.link_key is null then return false; end if;
  if not exists(select 1 from account_devices_private.enrollment_roots where device_id=claim.device_id and generation=claim.device_epoch)
     or not exists(select 1 from account_devices_private.owner_epochs where owner_id=claim.owner_id and epoch=claim.owner_epoch) then
    raise exception 'claim_superseded' using errcode='22023';
  end if;
  -- Reserve an activation version; keep the previous binding untouched until
  -- the hardware has durably applied that key and proves it in ACK.
  if claim.binding_version is null then
    version := nextval('account_devices_private.binding_versions');
    update account_devices_private.claims_v3 set binding_version=version where ticket_hash=claim.ticket_hash;
  end if;
  return false; -- The App must wait for durable activation acknowledged by the device.
end $$;

create function public.account_device_claim_state_v3(p_ticket text,p_device_id text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare claim account_devices_private.claims_v3%rowtype; root text; proof text;
begin
  if p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  select * into claim from account_devices_private.claims_v3
    where ticket_hash=sha256(convert_to(p_ticket,'UTF8')) and device_id=p_device_id;
  if not found or (claim.binding_version is null and claim.expires_at<=now()) then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  if claim.binding_version is null then return jsonb_build_object('state','pending'); end if;
  if (claim.acknowledged and not exists(select 1 from account_devices_private.bindings where owner_id=claim.owner_id
      and device_id=p_device_id and binding_version=claim.binding_version)) or
     (not claim.acknowledged and (not exists(select 1 from account_devices_private.enrollment_roots
      where device_id=p_device_id and generation=claim.device_epoch) or not exists(
      select 1 from account_devices_private.owner_epochs where owner_id=claim.owner_id and epoch=claim.owner_epoch))) then
    return jsonb_build_object('state','superseded');
  end if;
  select secret into root from account_devices_private.enrollment_roots where device_id=p_device_id;
  proof := encode(extensions.hmac(convert_to('watcher-activate-v3|'||claim.region||'|'||p_ticket||'|'||p_device_id||'|'||claim.link_key||'|'||claim.binding_version,'UTF8'),decode(root,'hex'),'sha256'),'hex');
  return jsonb_build_object('state',case when claim.acknowledged then 'active' else 'committed' end,
                           'binding_version',claim.binding_version::text,'proof',proof);
end $$;

create function public.ack_account_device_claim_v3(p_ticket text,p_device_id text,p_proof text)
returns void language plpgsql security definer set search_path='' as $$
declare claim account_devices_private.claims_v3%rowtype; root text; expected text;
begin
  if p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' or p_proof is null or p_proof !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(73141203);
  select * into claim from account_devices_private.claims_v3
    where ticket_hash=sha256(convert_to(p_ticket,'UTF8')) and device_id=p_device_id and binding_version is not null for update;
  if not found or claim.owner_id is null then
    raise exception 'claim_superseded' using errcode='22023';
  end if;
  select secret into root from account_devices_private.enrollment_roots where device_id=p_device_id;
  expected := encode(extensions.hmac(convert_to('watcher-ack-v3|'||claim.region||'|'||p_ticket||'|'||p_device_id||'|'||claim.link_key||'|'||claim.binding_version,'UTF8'),decode(root,'hex'),'sha256'),'hex');
  if expected is distinct from p_proof then raise exception 'invalid_device_claim' using errcode='22023'; end if;
  if claim.acknowledged then
    if not exists(select 1 from account_devices_private.bindings where owner_id=claim.owner_id
        and device_id=p_device_id and binding_version=claim.binding_version) then
      raise exception 'claim_superseded' using errcode='22023';
    end if;
    return;
  end if;
  if not exists(select 1 from account_devices_private.enrollment_roots where device_id=p_device_id
      and generation=claim.device_epoch) or not exists(select 1 from account_devices_private.owner_epochs
      where owner_id=claim.owner_id and epoch=claim.owner_epoch) then
    raise exception 'claim_superseded' using errcode='22023';
  end if;
  insert into account_devices_private.binding_events(owner_id,device_id,binding_version,reason)
    select owner_id,device_id,binding_version,'replaced' from account_devices_private.bindings
    where owner_id=claim.owner_id or device_id=p_device_id;
  update account_devices_private.owner_epochs set epoch=epoch+1 where owner_id=claim.owner_id or owner_id in
    (select owner_id from account_devices_private.bindings where device_id=p_device_id);
  delete from account_devices_private.bindings where owner_id=claim.owner_id or device_id=p_device_id;
  insert into account_devices_private.bindings(owner_id,device_id,link_key,binding_version)
    values(claim.owner_id,p_device_id,claim.link_key,claim.binding_version);
  insert into account_devices_private.credential_history(device_id,binding_version,link_key)
    values(p_device_id,claim.binding_version,claim.link_key);
  update account_devices_private.enrollment_roots set generation=claim.binding_version where device_id=p_device_id;
  insert into account_devices_private.binding_events(owner_id,device_id,binding_version,reason)
    values(claim.owner_id,p_device_id,claim.binding_version,'paired');
  update account_devices_private.claims_v3 set acknowledged=true where ticket_hash=claim.ticket_hash;
end $$;

-- Device checks only when Internet is available. A failed request never revokes
-- local credentials. The fresh regional nonce prevents replay of old decisions.
create function public.account_device_status_v3(p_device_id text,p_binding_version text,p_nonce text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare root text; key text; region text; decision text; proof text;
begin
  select d.region into region from account_devices_private.deployment d;
  if p_binding_version is null or p_binding_version !~ '^[1-9][0-9]{0,18}$'
     or (length(p_binding_version)=19 and p_binding_version>'9223372036854775807')
     or p_nonce is null or p_nonce !~ '^[0-9a-f]{64}$'
     or left(p_nonce,8) is distinct from (case when region='CN' then 'c3a3c3a3' else 'b3a3b3a3' end) then
    raise exception 'invalid_device_status' using errcode='22023';
  end if;
  select r.secret,c.link_key into root,key from account_devices_private.credential_history c
    join account_devices_private.enrollment_roots r using(device_id)
    where c.device_id=p_device_id and c.binding_version=p_binding_version::bigint;
  if root is null or key is null then raise exception 'invalid_device_status' using errcode='22023'; end if;
  decision := case when exists(select 1 from account_devices_private.bindings b where b.device_id=p_device_id
    and b.binding_version=p_binding_version::bigint) then 'active' else 'revoked' end;
  proof := encode(extensions.hmac(convert_to('watcher-'||decision||'-v3|'||region||'|'||p_nonce||'|'||p_device_id||'|'||key||'|'||p_binding_version,
    'UTF8'),decode(root,'hex'),'sha256'),'hex');
  return jsonb_build_object('state',decision,'proof',proof);
end $$;
revoke execute on function public.account_device_status_v3(text,text,text) from public,anon,authenticated;
grant execute on function public.account_device_status_v3(text,text,text) to anon;

-- Upgrade a legacy device without exposing its old key or changing ownership.
create function public.bootstrap_account_device_v3(p_device_id text,p_nonce text,p_proof text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare root text; key text; region text; version bigint; expected text; proof text;
begin
  select d.region into region from account_devices_private.deployment d;
  if region is null or p_nonce is null or p_nonce !~ '^[0-9a-f]{64}$'
     or left(p_nonce,8) is distinct from (case when region='CN' then 'c3a3c3a3' else 'b3a3b3a3' end)
     or p_proof is null or p_proof !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_bootstrap' using errcode='22023';
  end if;
  select r.secret,b.link_key,b.binding_version into root,key,version
    from account_devices_private.bindings b join account_devices_private.enrollment_roots r using(device_id)
    where b.device_id=p_device_id;
  if root is null or key is null then
    raise exception 'invalid_device_bootstrap' using errcode='22023';
  end if;
  expected := encode(extensions.hmac(convert_to('watcher-bootstrap-v3|'||region||'|'||p_nonce||'|'||p_device_id||'|'||key,
    'UTF8'),decode(root,'hex'),'sha256'),'hex');
  if expected is distinct from p_proof then
    raise exception 'invalid_device_bootstrap' using errcode='22023';
  end if;
  proof := encode(extensions.hmac(convert_to('watcher-active-v3|'||region||'|'||p_nonce||'|'||p_device_id||'|'||key||'|'||version,
    'UTF8'),decode(root,'hex'),'sha256'),'hex');
  return jsonb_build_object('binding_version',version::text,'proof',proof);
end $$;
revoke execute on function public.bootstrap_account_device_v3(text,text,text) from public,anon,authenticated;
grant execute on function public.bootstrap_account_device_v3(text,text,text) to anon;

drop function public.list_account_devices(uuid);
create function public.list_account_devices(p_owner_id uuid)
returns table(device_id text,binding_version text) language plpgsql stable security definer set search_path='' as $$
begin
  if auth.uid() is null or auth.uid() is distinct from p_owner_id then
    raise exception 'account_session_changed' using errcode='42501';
  end if;
  return query select b.device_id,b.binding_version::text from account_devices_private.bindings b where b.owner_id=p_owner_id;
end $$;

revoke execute on function public.claim_account_device(uuid,text,text) from public,anon,authenticated;
revoke execute on function public.prepare_account_device_claim(text) from public,anon,authenticated;
revoke execute on function public.stage_account_device_claim(text,text,text) from public,anon,authenticated;
revoke execute on function public.commit_account_device_claim(text) from public,anon,authenticated;
revoke execute on function public.prepare_account_device_claim_v3(text,text) from public,anon,authenticated;
revoke execute on function public.stage_account_device_claim_v3(text,text,text,text) from public,anon,authenticated;
revoke execute on function public.commit_account_device_claim_v3(text) from public,anon,authenticated;
revoke execute on function public.account_device_claim_state_v3(text,text) from public,anon,authenticated;
revoke execute on function public.ack_account_device_claim_v3(text,text,text) from public,anon,authenticated;
revoke execute on function public.list_account_devices(uuid) from public,anon,authenticated;
grant execute on function public.prepare_account_device_claim_v3(text,text) to authenticated;
grant execute on function public.commit_account_device_claim_v3(text) to authenticated;
grant execute on function public.list_account_devices(uuid) to authenticated;
grant execute on function public.stage_account_device_claim_v3(text,text,text,text) to anon;
grant execute on function public.account_device_claim_state_v3(text,text) to anon;
grant execute on function public.ack_account_device_claim_v3(text,text,text) to anon;
commit;
