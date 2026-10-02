-- Access for a limited time. See docs/cloud-operations.md.
--
-- A member asks for environments they do not have; an owner or admin
-- approves from the CLI, which signs a membership with the wider scope as
-- for any change of scope. This table keeps what the certificate does not
-- say: until when the wider part holds, and what the scope was before. When
-- the time is up the server stops serving the wider part by itself. Signing
-- the scope back and starting new keys takes an administrator's CLI.

create table public.access_grants (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references public.organizations on delete cascade,
  user_id      uuid not null references auth.users on delete cascade,
  scope        text[] not null check (cardinality(scope) between 1 and 16),
  minutes      integer not null check (minutes between 5 and 10080),
  reason       text not null default '' check (length(reason) <= 500),
  status       text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'ended')),
  requested_at timestamptz not null default now(),
  decided_by   uuid references auth.users,
  decided_at   timestamptz,
  expires_at   timestamptz,
  base_scope   text[],      -- the member's scope before it was widened
  listed_at    timestamptz  -- when what they fetched was listed for rotation
);
create index on public.access_grants (org_id, user_id);
alter table public.access_grants enable row level security;
create policy "own requests, or an admin's organization" on public.access_grants for select to authenticated
  using (user_id = auth.uid() or private.is_org_admin(org_id, auth.uid()));
revoke insert, update, delete, truncate on public.access_grants from anon, authenticated;

create or replace function public.request_access(p_org uuid, p_scope text[], p_minutes integer, p_reason text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); role text := private.role_in(p_org, me); s text; id uuid;
begin
  if role is null or role = 'auditor' then
    raise exception 'only members who hold keys ask for more access' using errcode = '42501';
  end if;
  foreach s in array p_scope loop
    if s !~ '^[a-z][a-z0-9-]{0,62}/(\*|[a-z][a-z0-9_.-]{0,62})$' then
      raise exception 'ask for project/environment or project/*; % is not one', s using errcode = '22023';
    end if;
  end loop;
  if exists (select 1 from public.access_grants g where g.org_id = p_org and g.user_id = me and g.status = 'pending') then
    raise exception 'you already have a request waiting' using errcode = '23505';
  end if;
  insert into public.access_grants (org_id, user_id, scope, minutes, reason) values (p_org, me, p_scope, p_minutes, coalesce(p_reason, ''))
  returning access_grants.id into id;
  perform private.audit(p_org, 'access.request', me::text, jsonb_build_object('scope', p_scope, 'minutes', p_minutes));
  return id;
end $$;

create or replace function public.deny_access(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); g public.access_grants;
begin
  select * into g from public.access_grants where id = p_id;
  if g.id is null or not private.is_org_admin(g.org_id, me) then
    raise exception 'only owners and admins decide requests' using errcode = '42501';
  end if;
  update public.access_grants set status = 'denied', decided_by = me, decided_at = now() where id = p_id and status = 'pending';
  if not found then
    raise exception 'that request is not waiting' using errcode = 'P0002';
  end if;
  perform private.audit(g.org_id, 'access.deny', g.user_id::text);
end $$;

-- Records an approval. The administrator's CLI has just signed the member's
-- membership with the wider scope; p_base_scope is the scope before it. The
-- two must add up to what the member holds now, so the record cannot say
-- less was granted than was.
create or replace function public.approve_access(p_id uuid, p_base_scope text[]) returns timestamptz
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); g public.access_grants; held text[]; until timestamptz;
begin
  select * into g from public.access_grants where id = p_id;
  if g.id is null or not private.is_org_admin(g.org_id, me) then
    raise exception 'only owners and admins decide requests' using errcode = '42501';
  end if;
  if g.status <> 'pending' then
    raise exception 'that request is not waiting' using errcode = 'P0002';
  end if;
  select scope into held from public.org_members where org_id = g.org_id and user_id = g.user_id and role <> 'removed';
  if held is null or not (held @> g.scope and held @> p_base_scope and (p_base_scope || g.scope) @> held) then
    raise exception 'the member''s signed scope is not their scope before plus what they asked for' using errcode = '22023';
  end if;
  until := now() + make_interval(mins => g.minutes);
  update public.access_grants set status = 'approved', decided_by = me, decided_at = now(), expires_at = until, base_scope = p_base_scope
  where id = p_id;
  perform private.audit(g.org_id, 'access.approve', g.user_id::text, jsonb_build_object('scope', g.scope, 'until', until));
  return until;
end $$;

-- Any later membership certificate for the member is an administrator's
-- decision about their scope, and ends the grants approved before it.
create or replace function private.end_grants() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  update public.access_grants set status = 'ended' where org_id = new.org_id and user_id = new.user_id and status = 'approved';
  return new;
end $$;
create trigger end_grants after insert on public.membership_certs
  for each row execute function private.end_grants();

-- Lists, for rotation, what the member fetched in the environments a grant
-- gave them, once the grant has ended. Called by the administrator's CLI
-- after it signed the scope back.
create or replace function public.close_access(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); g public.access_grants; task uuid;
begin
  select * into g from public.access_grants where id = p_id;
  if g.id is null or not private.is_org_admin(g.org_id, me) then
    raise exception 'only owners and admins end access' using errcode = '42501';
  end if;
  if g.status <> 'ended' or g.listed_at is not null then
    return;
  end if;
  update public.access_grants set listed_at = now() where id = p_id;
  if exists (
      select 1 from public.environments e join public.projects p on p.id = e.project_id
      where p.org_id = g.org_id and private.scope_allows(g.scope, p.slug, e.slug) and not private.scope_allows(g.base_scope, p.slug, e.slug)
        and exists (select 1 from public.audit_log a where a.org_id = g.org_id and a.action = 'environment.fetch'
                    and a.target = p.slug || '/' || e.slug and a.actor_user_id = g.user_id and a.at >= g.decided_at)) then
    insert into public.rotation_tasks (org_id, reason, subject_user_id, created_by) values (g.org_id, 'access ended', g.user_id, me) returning id into task;
    insert into public.rotation_items (task_id, secret_id)
    select task, s.id from public.secrets s join public.environments e on e.id = s.environment_id join public.projects p on p.id = e.project_id
    where p.org_id = g.org_id and private.scope_allows(g.scope, p.slug, e.slug) and not private.scope_allows(g.base_scope, p.slug, e.slug)
      and exists (select 1 from public.audit_log a where a.org_id = g.org_id and a.action = 'environment.fetch'
                  and a.target = p.slug || '/' || e.slug and a.actor_user_id = g.user_id and a.at >= g.decided_at);
  end if;
  perform private.audit(g.org_id, 'access.end', g.user_id::text, jsonb_build_object('scope', g.scope));
end $$;

-- Whether the member's hold on this environment came from a grant whose
-- time is up. Until an administrator signs the scope back, this is what
-- stops the server from serving it.
create or replace function private.grant_expired(p_org uuid, p_user uuid, p_project text, p_env text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.access_grants g
    where g.org_id = p_org and g.user_id = p_user and g.status = 'approved' and g.expires_at <= now()
      and private.scope_allows(g.scope, p_project, p_env) and not private.scope_allows(g.base_scope, p_project, p_env));
$$;

create or replace function private.can_use(p_env uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.environments e join public.projects p on p.id = e.project_id
    join public.org_members m on m.org_id = p.org_id and m.user_id = p_user
    where e.id = p_env and (
      m.role = 'owner' or
      (m.role in ('admin', 'maintainer', 'consumer') and private.scope_allows(m.scope, p.slug, e.slug)
        and not private.policy_denies(p.org_id, m.role, p.slug, e.slug)
        and not private.grant_expired(p.org_id, p_user, p.slug, e.slug))));
$$;

create or replace function private.can_administer(p_env uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.environments e join public.projects p on p.id = e.project_id
    join public.org_members m on m.org_id = p.org_id and m.user_id = p_user
    where e.id = p_env and (
      m.role = 'owner' or
      (m.role in ('admin', 'maintainer') and private.scope_allows(m.scope, p.slug, e.slug)
        and not private.policy_denies(p.org_id, m.role, p.slug, e.slug)
        and not private.grant_expired(p.org_id, p_user, p.slug, e.slug))));
$$;

revoke execute on function private.end_grants(), private.grant_expired(uuid, uuid, text, text) from public, anon, authenticated;
revoke execute on function public.request_access(uuid, text[], integer, text), public.deny_access(uuid),
  public.approve_access(uuid, text[]), public.close_access(uuid) from public, anon;
grant execute on function public.request_access(uuid, text[], integer, text), public.deny_access(uuid),
  public.approve_access(uuid, text[]), public.close_access(uuid) to authenticated;

-- For members' devices: whose hold on which environments has run out, so
-- they leave those members out when they wrap a new key, which would be
-- refused. It says who and where, as the member list does; not why.
create or replace function public.access_expired(p_org uuid) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if not private.is_member(p_org, private.caller()) then
    raise exception 'you are not a member of this organization' using errcode = '42501';
  end if;
  return (select coalesce(jsonb_agg(jsonb_build_object('user_id', g.user_id, 'scope', g.scope, 'base_scope', g.base_scope)), '[]')
    from public.access_grants g where g.org_id = p_org and g.status = 'approved' and g.expires_at <= now());
end $$;
revoke execute on function public.access_expired(uuid) from public, anon;
grant execute on function public.access_expired(uuid) to authenticated;
