-- Sensitive secrets. See docs/managed-keys.md.
--
-- A sensitive secret never reaches a member's machine. Its value is
-- encrypted to the server's proxy identity, a key that is configuration of
-- the server and is not in this database, so a copy of the database alone
-- still reveals nothing. Members read names, versions, and allowed hosts;
-- the ciphertext is returned only to the server, to forward a request.

create table public.sensitive_secrets (
  id              uuid primary key default gen_random_uuid(),
  environment_id  uuid not null references public.environments on delete cascade,
  name            text not null check (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  current_version bigint not null default 0,
  created_at      timestamptz not null default now(),
  unique (environment_id, name)
);

create table public.sensitive_versions (
  secret_id        uuid not null references public.sensitive_secrets on delete cascade,
  version          bigint not null check (version >= 1),
  hosts            text[] not null check (cardinality(hosts) between 1 and 16),
  proxy_recipient  text not null check (proxy_recipient like 'age1%'),
  sealed           bytea not null check (length(sealed) <= 131072),
  writer_user_id   uuid not null references auth.users,
  writer_device_id text not null,
  signature        bytea not null check (length(signature) = 64),
  created_at       timestamptz not null default now(),
  primary key (secret_id, version)
);

alter table public.sensitive_secrets enable row level security;
alter table public.sensitive_versions enable row level security;
create policy "member reads sensitive names" on public.sensitive_secrets for select to authenticated using (
  exists (select 1 from public.environments e join public.projects p on p.id = e.project_id
          where e.id = environment_id and private.is_member(p.org_id, auth.uid())));
-- sensitive_versions: no policy. Functions return what each caller may have.
revoke insert, update, delete, truncate on public.sensitive_secrets, public.sensitive_versions from anon, authenticated;
revoke select on public.sensitive_versions from anon, authenticated;

-- One name is one secret: an environment cannot hold an ordinary secret and
-- a sensitive one under the same name.
create or replace function private.one_kind_per_name() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_table_name = 'secrets' and exists (
      select 1 from public.sensitive_secrets s where s.environment_id = new.environment_id and s.name = new.name) then
    raise exception '% is a sensitive secret; set it with --sensitive', new.name using errcode = '23505';
  end if;
  if tg_table_name = 'sensitive_secrets' and exists (
      select 1 from public.secrets s where s.environment_id = new.environment_id and s.name = new.name) then
    raise exception '% already exists as an ordinary secret, which members have read; use another name', new.name using errcode = '23505';
  end if;
  return new;
end $$;
create trigger one_kind_per_name before insert on public.secrets
  for each row execute function private.one_kind_per_name();
create trigger one_kind_per_name before insert on public.sensitive_secrets
  for each row execute function private.one_kind_per_name();

-- Writes the next version of a sensitive secret, sealed on an owner's or an
-- admin's device. Marking a secret sensitive is theirs alone to decide.
create or replace function public.put_sensitive_version(p_env uuid, p_name text, p_version bigint, p_hosts text[],
  p_proxy_recipient text, p_sealed bytea, p_device text, p_signature bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; s uuid; current bigint;
begin
  select * into info from private.env_info(p_env);
  if info.org_id is null or not private.is_org_admin(info.org_id, me) or not private.can_administer(p_env, me) then
    raise exception 'only owners and admins of this environment set sensitive secrets' using errcode = '42501';
  end if;
  insert into public.sensitive_secrets (environment_id, name) values (p_env, p_name)
  on conflict (environment_id, name) do nothing;
  select id, current_version into s, current from public.sensitive_secrets
  where environment_id = p_env and name = p_name for update;
  if p_version <> current + 1 then
    raise exception 'version % is not the next one (%); sync and try again', p_version, current + 1 using errcode = '40001';
  end if;
  insert into public.sensitive_versions (secret_id, version, hosts, proxy_recipient, sealed, writer_user_id, writer_device_id, signature)
  values (s, p_version, p_hosts, p_proxy_recipient, p_sealed, me, p_device, p_signature);
  update public.sensitive_secrets set current_version = p_version where id = s;
  perform private.audit(info.org_id, 'secret.sensitive', info.project || '/' || info.env || '/' || p_name,
    jsonb_build_object('version', p_version, 'hosts', p_hosts), p_device);
end $$;

-- The sensitive secrets of an organization as members see them: where each
-- may be sent, who marked it, and what their device signed. No ciphertext.
create or replace function public.sensitive_in_org(p_org uuid) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if not private.is_member(p_org, private.caller()) then
    raise exception 'you are not a member of this organization' using errcode = '42501';
  end if;
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'environment_id', s.environment_id, 'name', s.name, 'version', v.version, 'hosts', v.hosts,
      'proxy_recipient', v.proxy_recipient, 'sealed_hash', encode(extensions.digest(v.sealed, 'sha256'), 'base64'),
      'writer_user_id', v.writer_user_id, 'writer_device_id', v.writer_device_id,
      'signature', encode(v.signature, 'base64')) order by s.name), '[]')
    from public.sensitive_secrets s
    join public.sensitive_versions v on v.secret_id = s.id and v.version = s.current_version
    join public.environments e on e.id = s.environment_id
    join public.projects p on p.id = e.project_id
    where p.org_id = p_org);
end $$;

-- For the server only: the ciphertext of a sensitive secret, to forward a
-- request with its value.
create or replace function public.sensitive_for_proxy(p_env uuid, p_name text) returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('org_id', p.org_id, 'project_id', p.id, 'environment_id', e.id, 'name', s.name,
    'version', v.version, 'sealed', encode(v.sealed, 'base64'))
  from public.sensitive_secrets s
  join public.sensitive_versions v on v.secret_id = s.id and v.version = s.current_version
  join public.environments e on e.id = s.environment_id
  join public.projects p on p.id = e.project_id
  where s.environment_id = p_env and s.name = p_name;
$$;

revoke execute on function private.one_kind_per_name() from public, anon, authenticated;
revoke execute on function public.put_sensitive_version(uuid, text, bigint, text[], text, bytea, text, bytea) from public, anon;
revoke execute on function public.sensitive_in_org(uuid) from public, anon;
revoke execute on function public.sensitive_for_proxy(uuid, text) from public, anon, authenticated;
grant execute on function public.put_sensitive_version(uuid, text, bigint, text[], text, bytea, text, bytea) to authenticated;
grant execute on function public.sensitive_in_org(uuid) to authenticated;
grant execute on function public.sensitive_for_proxy(uuid, text) to service_role;
