begin;

-- Follow-up only: 202611140001 is already deployed and remains immutable.
create or replace function public.account_device_claim_state_v3(p_ticket text,p_device_id text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare claim account_devices_private.claims_v3%rowtype; root text; proof text; decision text;
begin
  if p_ticket is null or p_ticket !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_claim' using errcode='22023';
  end if;
  -- Match ACK/commit's lock: otherwise an ACK between reading acknowledged
  -- and checking epochs could turn its own success into a signed false abort.
  perform pg_advisory_xact_lock(73141203);
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
    select secret into root from account_devices_private.enrollment_roots where device_id=p_device_id;
    -- An acknowledged key was subsequently revoked: never restore a predecessor.
    -- An unacknowledged key may be aborted, but the device independently checks
    -- any predecessor against its own region before restoring authorization.
    decision := case when claim.acknowledged then 'revoked' else 'abort' end;
    proof := encode(extensions.hmac(convert_to('watcher-'||decision||'-v3|'||claim.region||'|'||p_ticket||'|'||p_device_id||'|'||claim.link_key||'|'||claim.binding_version,
      'UTF8'),decode(root,'hex'),'sha256'),'hex');
    return jsonb_build_object('state',case when claim.acknowledged then 'revoked' else 'aborted' end,
      'binding_version',claim.binding_version::text,'proof',proof);
  end if;
  select secret into root from account_devices_private.enrollment_roots where device_id=p_device_id;
  proof := encode(extensions.hmac(convert_to('watcher-activate-v3|'||claim.region||'|'||p_ticket||'|'||p_device_id||'|'||claim.link_key||'|'||claim.binding_version,'UTF8'),decode(root,'hex'),'sha256'),'hex');
  return jsonb_build_object('state',case when claim.acknowledged then 'active' else 'committed' end,
                           'binding_version',claim.binding_version::text,'proof',proof);
end $$;

create or replace function public.bootstrap_account_device_v3(p_device_id text,p_nonce text,p_proof text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare root text; region text; credential record; expected text; proof text; decision text;
begin
  select d.region into region from account_devices_private.deployment d;
  if region is null or p_nonce is null or p_nonce !~ '^[0-9a-f]{64}$'
     or left(p_nonce,8) is distinct from (case when region='CN' then 'c3a3c3a3' else 'b3a3b3a3' end)
     or p_proof is null or p_proof !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_device_bootstrap' using errcode='22023';
  end if;
  select r.secret into root from account_devices_private.enrollment_roots r where r.device_id=p_device_id;
  if root is null then raise exception 'invalid_device_bootstrap' using errcode='22023'; end if;
  -- The key stays private: match a hardware-root proof against the history for
  -- this device, including credentials revoked before its first firmware boot.
  for credential in select c.link_key,c.binding_version from account_devices_private.credential_history c
    where c.device_id=p_device_id order by c.binding_version desc loop
    expected := encode(extensions.hmac(convert_to('watcher-bootstrap-v3|'||region||'|'||p_nonce||'|'||p_device_id||'|'||credential.link_key,
      'UTF8'),decode(root,'hex'),'sha256'),'hex');
    if expected = p_proof then
      decision := case when exists(select 1 from account_devices_private.bindings b where b.device_id=p_device_id
        and b.binding_version=credential.binding_version and b.link_key=credential.link_key) then 'active' else 'revoked' end;
      proof := encode(extensions.hmac(convert_to('watcher-'||decision||'-v3|'||region||'|'||p_nonce||'|'||p_device_id||'|'||credential.link_key||'|'||credential.binding_version,
        'UTF8'),decode(root,'hex'),'sha256'),'hex');
      return jsonb_build_object('state',decision,'binding_version',credential.binding_version::text,'proof',proof);
    end if;
  end loop;
  raise exception 'invalid_device_bootstrap' using errcode='22023';
end $$;

commit;
