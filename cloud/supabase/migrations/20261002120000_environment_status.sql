-- Who has the current values of an environment. See docs/managed-keys.md.
--
-- When a value is replaced, its owner wants to know which devices and
-- tokens already have the new one. The server knows when each of them last
-- fetched the environment (the audit log) and when each value was written,
-- so a device is behind when its last fetch is older than a value.
--
-- A transition is until when the previous value is still expected to work at
-- whatever issued it. It is information for people: nothing enforces it.

alter table public.secret_versions add column transition_until timestamptz;

-- Records until when the value before the current one is expected to work.
create or replace function public.set_transition(p_env uuid, p_name text, p_until timestamptz) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record;
begin
  select * into info from private.env_info(p_env);
  if not private.can_administer(p_env, me) then
    raise exception 'you cannot write to this environment' using errcode = '42501';
  end if;
  update public.secret_versions v set transition_until = p_until
  from public.secrets s
  where s.environment_id = p_env and s.name = p_name and v.secret_id = s.id and v.version = s.current_version;
  if not found then
    raise exception 'no secret % in this environment', p_name using errcode = 'P0002';
  end if;
  perform private.audit(info.org_id, 'secret.transition', info.project || '/' || info.env || '/' || p_name,
    jsonb_build_object('until', p_until));
end $$;

-- The current values of an environment, by name and time only, and when
-- each device and token last fetched it. For those who administer the
-- environment and for whoever reads the audit log, which holds the same.
create or replace function public.environment_status(p_env uuid) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare me uuid := private.caller(); info record;
begin
  select * into info from private.env_info(p_env);
  if info.org_id is null or not (private.can_administer(p_env, me)
      or coalesce(private.role_in(info.org_id, me) in ('owner', 'admin', 'auditor'), false)) then
    raise exception 'you cannot see who synced this environment' using errcode = '42501';
  end if;
  return jsonb_build_object(
    'secrets', (select coalesce(jsonb_agg(jsonb_build_object(
        'name', s.name, 'version', v.version, 'written_at', v.created_at, 'transition_until', v.transition_until) order by s.name), '[]')
      from public.secrets s join public.secret_versions v on v.secret_id = s.id and v.version = s.current_version
      where s.environment_id = p_env),
    'fetches', (select coalesce(jsonb_agg(jsonb_build_object(
        'user_id', f.actor_user_id, 'device_id', f.actor_device_id, 'token_id', f.actor_token_id, 'last_fetch', f.last_fetch)
        order by f.last_fetch desc), '[]')
      from (select a.actor_user_id, a.actor_device_id, a.actor_token_id, max(a.at) as last_fetch
            from public.audit_log a
            where a.org_id = info.org_id and a.action = 'environment.fetch' and a.target = info.project || '/' || info.env
            group by a.actor_user_id, a.actor_device_id, a.actor_token_id) f));
end $$;

revoke execute on function public.set_transition(uuid, text, timestamptz) from public, anon;
revoke execute on function public.environment_status(uuid) from public, anon;
grant execute on function public.set_transition(uuid, text, timestamptz) to authenticated;
grant execute on function public.environment_status(uuid) to authenticated;
