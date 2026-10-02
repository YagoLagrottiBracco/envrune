-- Using a sensitive secret. See docs/managed-keys.md.
--
-- A member's envrune sends the server a request to forward, naming the
-- sensitive secrets whose placeholders it contains. Before the server opens
-- one, it asks here, as that member, whether they may use the environment
-- from that device. Use is counted per member, device, host, and hour; the
-- first request of each hour goes to the audit log, so the log shows who
-- used a secret and when without growing by one entry per request.

create table public.sensitive_use (
  secret_id  uuid not null references public.sensitive_secrets on delete cascade,
  user_id    uuid not null references auth.users on delete cascade,
  device_id  text not null,
  host       text not null,
  hour       timestamptz not null,
  requests   bigint not null default 0,
  primary key (secret_id, user_id, device_id, host, hour)
);
alter table public.sensitive_use enable row level security;
create policy "admin or auditor reads use of sensitive secrets" on public.sensitive_use for select to authenticated using (
  exists (select 1 from public.sensitive_secrets s join public.environments e on e.id = s.environment_id
          join public.projects p on p.id = e.project_id
          where s.id = secret_id and coalesce(private.role_in(p.org_id, auth.uid()) in ('owner', 'admin', 'auditor'), false)));
revoke insert, update, delete, truncate on public.sensitive_use from anon, authenticated;

-- Called by the server as the member. Refuses a member who may not use the
-- environment and a device that is not approved. The server asks twice: with
-- p_record false before it opens the secret, and with p_record true once it
-- knows the request goes to a host the secret allows, which records the use.
create or replace function public.sensitive_forward(p_env uuid, p_name text, p_device text, p_host text, p_record boolean) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; s uuid; first boolean;
begin
  select * into info from private.env_info(p_env);
  if info.org_id is null or not private.can_use(p_env, me) then
    raise exception 'you cannot use this environment' using errcode = '42501';
  end if;
  if not exists (select 1 from public.devices d where d.user_id = me and d.id = p_device
                 and d.signature is not null and d.revoked_at is null) then
    raise exception 'this device is not approved' using errcode = '42501';
  end if;
  select id into s from public.sensitive_secrets where environment_id = p_env and name = p_name;
  if s is null then
    raise exception 'no sensitive secret % in this environment', p_name using errcode = 'P0002';
  end if;
  if not p_record then
    return;
  end if;
  insert into public.sensitive_use (secret_id, user_id, device_id, host, hour, requests)
  values (s, me, p_device, p_host, date_trunc('hour', now()), 1)
  on conflict (secret_id, user_id, device_id, host, hour) do update set requests = public.sensitive_use.requests + 1
  returning (requests = 1) into first;
  if first then
    perform private.audit(info.org_id, 'secret.forward', info.project || '/' || info.env || '/' || p_name,
      jsonb_build_object('host', p_host), p_device);
  end if;
end $$;

revoke execute on function public.sensitive_forward(uuid, text, text, text, boolean) from public, anon;
grant execute on function public.sensitive_forward(uuid, text, text, text, boolean) to authenticated;
