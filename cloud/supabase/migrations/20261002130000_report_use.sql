-- Use of values, as devices report it. See docs/managed-keys.md.
--
-- The server sees fetches, not use: a device can run commands for weeks
-- from one fetch. When a command injects values its user may use but not
-- see, the device notes which secrets and when, and reports the notes the
-- next time it is online. They are the device's own account, marked so in
-- the audit log: they answer what a team uses and when, not whether
-- someone did not use a value.

create or replace function public.report_use(p_env uuid, p_device text, p_uses jsonb) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; u jsonb;
begin
  select * into info from private.env_info(p_env);
  if info.org_id is null or not private.can_use(p_env, me) then
    raise exception 'you cannot use this environment' using errcode = '42501';
  end if;
  if not exists (select 1 from public.devices d where d.user_id = me and d.id = p_device
                 and d.signature is not null and d.revoked_at is null) then
    raise exception 'this device is not approved' using errcode = '42501';
  end if;
  if jsonb_typeof(p_uses) <> 'array' or jsonb_array_length(p_uses) > 200 then
    raise exception 'report up to 200 uses at a time' using errcode = '22023';
  end if;
  for u in select * from jsonb_array_elements(p_uses) loop
    if jsonb_typeof(u->'names') <> 'array' or (u->>'at') is null then
      raise exception 'a use has names and a time' using errcode = '22023';
    end if;
    perform private.audit(info.org_id, 'secret.use', info.project || '/' || info.env,
      jsonb_build_object('names', u->'names', 'at', (u->>'at')::timestamptz, 'reported_by_device', true), p_device);
  end loop;
end $$;

revoke execute on function public.report_use(uuid, text, jsonb) from public, anon;
grant execute on function public.report_use(uuid, text, jsonb) to authenticated;
