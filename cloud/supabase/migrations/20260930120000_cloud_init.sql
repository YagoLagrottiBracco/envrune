-- EnvRune Cloud schema. See docs/cloud-crypto.md.
--
-- The database stores ciphertext, wrapped keys, public keys, signatures, and
-- metadata. It never sees a value or a key that decrypts one. Row-level
-- security decides who may fetch data; encryption decides who can read it.
--
-- Rules for this schema:
--   * Every table has RLS enabled. Authenticated users get SELECT policies on
--     metadata only; there are no INSERT, UPDATE, or DELETE policies.
--   * Every write goes through a SECURITY DEFINER function in public that
--     checks the caller's role, and appends to the audit log in the same
--     transaction.
--   * Ciphertext and wrapped keys are readable only through fetch functions,
--     which record the fetch in the audit log.
--   * Times that signatures cover are stored as microseconds (bigint), exactly
--     as signed.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- ---------------------------------------------------------------- tables

create table public.profiles (
  user_id         uuid primary key references auth.users on delete cascade,
  account_key     bytea not null check (length(account_key) = 32),
  recovery_backup bytea not null,
  created_at      timestamptz not null default now()
);

create table public.organizations (
  id         uuid primary key default gen_random_uuid(),
  slug       text not null unique check (slug ~ '^[a-z][a-z0-9-]{1,38}$'),
  name       text not null check (length(name) between 1 and 100),
  created_by uuid not null references auth.users,
  created_at timestamptz not null default now()
);

-- The account keys every member pins as the organization's root.
create table public.org_roots (
  org_id      uuid not null references public.organizations on delete cascade,
  user_id     uuid not null references auth.users,
  account_key bytea not null check (length(account_key) = 32),
  primary key (org_id, user_id)
);

-- Every membership certificate ever issued; clients verify them.
create table public.membership_certs (
  id           bigint generated always as identity primary key,
  org_id       uuid not null references public.organizations on delete cascade,
  user_id      uuid not null references auth.users,
  account_key  bytea not null check (length(account_key) = 32),
  role         text not null check (role in ('owner', 'admin', 'maintainer', 'consumer', 'auditor', 'removed')),
  scope        text[] not null,
  issued_at_us bigint not null,
  issuer_id    uuid not null references auth.users,
  signature    bytea not null check (length(signature) = 64)
);
create index on public.membership_certs (org_id, user_id);

-- The current role of each member, derived from the newest certificate. RLS
-- policies use it; clients do not trust it.
create table public.org_members (
  org_id     uuid not null references public.organizations on delete cascade,
  user_id    uuid not null references auth.users,
  role       text not null check (role in ('owner', 'admin', 'maintainer', 'consumer', 'auditor', 'removed')),
  scope      text[] not null,
  updated_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

-- Devices and recovery recipients. A device is pending until its
-- certificate signature is set.
create table public.devices (
  user_id       uuid not null references auth.users on delete cascade,
  id            text not null check (length(id) between 1 and 64),
  kind          text not null check (kind in ('device', 'recovery')),
  name          text not null default '',
  age_recipient text not null check (age_recipient like 'age1%'),
  signing_key   bytea check (signing_key is null or length(signing_key) = 32),
  created_at_us bigint not null,
  signature     bytea check (signature is null or length(signature) = 64),
  -- The account private key, encrypted with age to this device by the
  -- trusted device that approved it, so the new device can sign too.
  account_key_wrapped bytea,
  revoked_at    timestamptz,
  registered_at timestamptz not null default now(),
  primary key (user_id, id),
  check (kind = 'recovery' or signing_key is not null)
);

create table public.projects (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations on delete cascade,
  slug       text not null check (slug ~ '^[a-z][a-z0-9-]{0,62}$'),
  name       text not null,
  created_at timestamptz not null default now(),
  unique (org_id, slug)
);

create table public.environments (
  id              uuid primary key default gen_random_uuid(),
  project_id      uuid not null references public.projects on delete cascade,
  slug            text not null check (slug ~ '^[a-z][a-z0-9_.-]{0,62}$'),
  epoch           bigint not null default 1 check (epoch >= 1),
  needs_rotation  boolean not null default false,
  created_at      timestamptz not null default now(),
  unique (project_id, slug)
);

create table public.machine_tokens (
  id            text primary key,
  org_id        uuid not null references public.organizations on delete cascade,
  created_by    uuid not null references auth.users,
  name          text not null default '',
  age_recipient text not null check (age_recipient like 'age1%'),
  scope         text[] not null,
  created_at_us bigint not null,
  signature     bytea not null check (length(signature) = 64),
  secret_hash   bytea not null check (length(secret_hash) = 32),
  expires_at    timestamptz not null,
  revoked_at    timestamptz,
  last_used_at  timestamptz
);

-- An environment key of one epoch, encrypted to one recipient: a device or
-- the recovery recipient of a user, or a machine token.
create table public.wrapped_keys (
  environment_id     uuid not null references public.environments on delete cascade,
  epoch              bigint not null,
  recipient_user_id  uuid references auth.users on delete cascade,
  recipient_token_id text references public.machine_tokens on delete cascade,
  recipient_id       text not null,
  wrapped            bytea not null,
  wrapper_user_id    uuid not null references auth.users,
  wrapper_device_id  text not null,
  signature          bytea not null check (length(signature) = 64),
  created_at         timestamptz not null default now(),
  check ((recipient_user_id is null) <> (recipient_token_id is null))
);
create unique index wrapped_keys_recipient on public.wrapped_keys
  (environment_id, epoch, coalesce(recipient_user_id::text, 'token'), recipient_id);

create table public.secrets (
  id              uuid primary key default gen_random_uuid(),
  environment_id  uuid not null references public.environments on delete cascade,
  name            text not null check (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  current_version bigint not null default 0,
  created_at      timestamptz not null default now(),
  unique (environment_id, name)
);

create table public.secret_versions (
  secret_id        uuid not null references public.secrets on delete cascade,
  version          bigint not null check (version >= 1),
  epoch            bigint not null,
  nonce            bytea not null check (length(nonce) = 24),
  ciphertext       bytea not null check (length(ciphertext) <= 65536),
  writer_user_id   uuid not null references auth.users,
  writer_device_id text not null,
  signature        bytea not null check (length(signature) = 64),
  created_at       timestamptz not null default now(),
  primary key (secret_id, version)
);

-- Guided rotation after a member or a token leaves.
create table public.rotation_tasks (
  id              uuid primary key default gen_random_uuid(),
  org_id          uuid not null references public.organizations on delete cascade,
  reason          text not null,
  subject_user_id uuid references auth.users,
  subject_token   text,
  created_by      uuid not null references auth.users,
  created_at      timestamptz not null default now()
);

create table public.rotation_items (
  task_id    uuid not null references public.rotation_tasks on delete cascade,
  secret_id  uuid not null references public.secrets on delete cascade,
  status     text not null default 'pending' check (status in ('pending', 'rotated', 'accepted')),
  updated_by uuid references auth.users,
  updated_at timestamptz,
  primary key (task_id, secret_id)
);

-- Append-only, hash-chained audit log.
create table public.audit_log (
  id              bigint generated always as identity primary key,
  org_id          uuid not null references public.organizations on delete cascade,
  at              timestamptz not null default now(),
  actor_user_id   uuid,
  actor_device_id text,
  actor_token_id  text,
  action          text not null,
  target          text not null default '',
  detail          jsonb not null default '{}',
  prev_hash       bytea,
  hash            bytea not null
);
create index on public.audit_log (org_id, id);

-- ---------------------------------------------------------------- audit

create or replace function private.audit_chain() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  -- One writer at a time per organization, so the chain has no forks.
  perform pg_advisory_xact_lock(hashtext('envrune-audit:' || new.org_id::text));
  select a.hash into new.prev_hash from public.audit_log a where a.org_id = new.org_id order by a.id desc limit 1;
  new.at := now();
  new.hash := extensions.digest(
    coalesce(new.prev_hash, ''::bytea) ||
    convert_to(concat_ws(E'\x1f', new.org_id, to_char(new.at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      new.actor_user_id, new.actor_device_id, new.actor_token_id, new.action, new.target, new.detail::text), 'UTF8'),
    'sha256');
  return new;
end $$;

create trigger audit_chain before insert on public.audit_log
  for each row execute function private.audit_chain();

create or replace function private.audit_immutable() returns trigger
language plpgsql as $$
begin
  raise exception 'the audit log is append-only';
end $$;

create trigger audit_no_update before update or delete on public.audit_log
  for each row execute function private.audit_immutable();
create trigger audit_no_truncate before truncate on public.audit_log
  for each statement execute function private.audit_immutable();

create or replace function private.audit(p_org uuid, p_action text, p_target text, p_detail jsonb default '{}',
  p_device text default null, p_token text default null) returns void
language sql security definer set search_path = '' as $$
  insert into public.audit_log (org_id, actor_user_id, actor_device_id, actor_token_id, action, target, detail, hash)
  values (p_org, auth.uid(), p_device, p_token, p_action, p_target, coalesce(p_detail, '{}'), ''::bytea);
$$;

-- ---------------------------------------------------------------- helpers

create or replace function private.caller() returns uuid
language plpgsql stable as $$
begin
  if auth.uid() is null then
    raise exception 'sign in first' using errcode = '28000';
  end if;
  return auth.uid();
end $$;

create or replace function private.role_in(p_org uuid, p_user uuid) returns text
language sql stable security definer set search_path = '' as $$
  select m.role from public.org_members m where m.org_id = p_org and m.user_id = p_user and m.role <> 'removed';
$$;

create or replace function private.scope_allows(p_scope text[], p_project text, p_env text) returns boolean
language sql immutable as $$
  select '*' = any(p_scope) or (p_project || '/*') = any(p_scope) or (p_project || '/' || p_env) = any(p_scope);
$$;

-- The organization, project and environment slugs of an environment.
create or replace function private.env_info(p_env uuid, out org_id uuid, out project text, out env text, out epoch bigint)
language sql stable security definer set search_path = '' as $$
  select p.org_id, p.slug, e.slug, e.epoch
  from public.environments e join public.projects p on p.id = e.project_id where e.id = p_env;
$$;

-- Whether the user receives the environment key (roots and owners: all).
create or replace function private.can_use(p_env uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.environments e join public.projects p on p.id = e.project_id
    join public.org_members m on m.org_id = p.org_id and m.user_id = p_user
    where e.id = p_env and (
      m.role = 'owner' or
      (m.role in ('admin', 'maintainer', 'consumer') and private.scope_allows(m.scope, p.slug, e.slug))));
$$;

-- Whether the user may write values and wrap keys.
create or replace function private.can_administer(p_env uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.environments e join public.projects p on p.id = e.project_id
    join public.org_members m on m.org_id = p.org_id and m.user_id = p_user
    where e.id = p_env and (
      m.role = 'owner' or
      (m.role in ('admin', 'maintainer') and private.scope_allows(m.scope, p.slug, e.slug))));
$$;

create or replace function private.is_org_admin(p_org uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(private.role_in(p_org, p_user) in ('owner', 'admin'), false);
$$;

create or replace function private.is_member(p_org uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select private.role_in(p_org, p_user) is not null;
$$;

-- ---------------------------------------------------------------- RLS

alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.org_roots enable row level security;
alter table public.membership_certs enable row level security;
alter table public.org_members enable row level security;
alter table public.devices enable row level security;
alter table public.projects enable row level security;
alter table public.environments enable row level security;
alter table public.machine_tokens enable row level security;
alter table public.wrapped_keys enable row level security;
alter table public.secrets enable row level security;
alter table public.secret_versions enable row level security;
alter table public.rotation_tasks enable row level security;
alter table public.rotation_items enable row level security;
alter table public.audit_log enable row level security;

-- Public keys of fellow members, which clients need to verify certificates.
create policy "own or fellow member profile" on public.profiles for select to authenticated using (
  user_id = auth.uid() or exists (
    select 1 from public.org_members a join public.org_members b on a.org_id = b.org_id
    where a.user_id = auth.uid() and a.role <> 'removed' and b.user_id = profiles.user_id));

create policy "member reads organization" on public.organizations for select to authenticated
  using (private.is_member(id, auth.uid()));
create policy "member reads roots" on public.org_roots for select to authenticated
  using (private.is_member(org_id, auth.uid()));
create policy "member reads certificates" on public.membership_certs for select to authenticated
  using (private.is_member(org_id, auth.uid()));
create policy "member reads members" on public.org_members for select to authenticated
  using (private.is_member(org_id, auth.uid()));
create policy "member reads fellow devices" on public.devices for select to authenticated using (
  user_id = auth.uid() or exists (
    select 1 from public.org_members a join public.org_members b on a.org_id = b.org_id
    where a.user_id = auth.uid() and a.role <> 'removed' and b.user_id = devices.user_id));
create policy "member reads projects" on public.projects for select to authenticated
  using (private.is_member(org_id, auth.uid()));
create policy "member reads environments" on public.environments for select to authenticated using (
  exists (select 1 from public.projects p where p.id = project_id and private.is_member(p.org_id, auth.uid())));
create policy "member reads secret names" on public.secrets for select to authenticated using (
  exists (select 1 from public.environments e join public.projects p on p.id = e.project_id
          where e.id = environment_id and private.is_member(p.org_id, auth.uid())));
create policy "admin reads tokens" on public.machine_tokens for select to authenticated
  using (private.is_org_admin(org_id, auth.uid()));
create policy "member reads rotation tasks" on public.rotation_tasks for select to authenticated
  using (private.is_member(org_id, auth.uid()));
create policy "member reads rotation items" on public.rotation_items for select to authenticated using (
  exists (select 1 from public.rotation_tasks t where t.id = task_id and private.is_member(t.org_id, auth.uid())));
create policy "admin or auditor reads audit" on public.audit_log for select to authenticated
  using (coalesce(private.role_in(org_id, auth.uid()) in ('owner', 'admin', 'auditor'), false));
-- wrapped_keys and secret_versions: no policy. Only the fetch functions,
-- which record each fetch, return them.

revoke insert, update, delete, truncate on all tables in schema public from anon, authenticated;
revoke select on public.wrapped_keys, public.secret_versions from anon, authenticated;

-- ---------------------------------------------------------------- accounts and devices

create or replace function public.register_account(p_account_key bytea, p_recovery_backup bytea,
  p_recovery_recipient text, p_recovery_created_at_us bigint, p_recovery_signature bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  if exists (select 1 from public.profiles where user_id = me) then
    raise exception 'this account is already registered; recover it with the recovery key' using errcode = '23505';
  end if;
  insert into public.profiles (user_id, account_key, recovery_backup) values (me, p_account_key, p_recovery_backup);
  insert into public.devices (user_id, id, kind, name, age_recipient, created_at_us, signature)
  values (me, 'recovery', 'recovery', 'recovery key', p_recovery_recipient, p_recovery_created_at_us, p_recovery_signature);
end $$;

-- The recovery backup, for a device restoring the account.
create or replace function public.recovery_backup() returns bytea
language sql stable security definer set search_path = '' as $$
  select recovery_backup from public.profiles where user_id = private.caller();
$$;

-- A new device of the caller. Without a signature it waits for approval by
-- a trusted device; with one, it was certified with the account key.
create or replace function public.register_device(p_id text, p_name text, p_age_recipient text,
  p_signing_key bytea, p_created_at_us bigint, p_signature bytea default null) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  insert into public.devices (user_id, id, kind, name, age_recipient, signing_key, created_at_us, signature)
  values (me, p_id, 'device', p_name, p_age_recipient, p_signing_key, p_created_at_us, p_signature);
end $$;

-- A trusted device of the caller certifies a pending one, and hands it the
-- account key encrypted to it.
create or replace function public.approve_device(p_id text, p_created_at_us bigint, p_signature bytea,
  p_account_key_wrapped bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  update public.devices set created_at_us = p_created_at_us, signature = p_signature, account_key_wrapped = p_account_key_wrapped
  where user_id = me and id = p_id and kind = 'device' and signature is null and revoked_at is null;
  if not found then
    raise exception 'no pending device % for this account', p_id using errcode = 'P0002';
  end if;
end $$;

create or replace function public.revoke_device(p_id text) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid;
begin
  update public.devices set revoked_at = now() where user_id = me and id = p_id and kind = 'device' and revoked_at is null;
  if not found then
    raise exception 'no active device % for this account', p_id using errcode = 'P0002';
  end if;
  -- Its wrapped keys go; it held those keys, so its environments need rotation.
  update public.environments e set needs_rotation = true
  where exists (select 1 from public.wrapped_keys w where w.environment_id = e.id and w.recipient_user_id = me and w.recipient_id = p_id);
  delete from public.wrapped_keys where recipient_user_id = me and recipient_id = p_id;
  for o in select m.org_id from public.org_members m where m.user_id = me and m.role <> 'removed' loop
    perform private.audit(o, 'device.revoke', p_id, '{}', p_id);
  end loop;
end $$;

-- ---------------------------------------------------------------- organizations and members

create or replace function public.create_organization(p_slug text, p_name text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); key bytea; o uuid;
begin
  select account_key into key from public.profiles where user_id = me;
  if key is null then
    raise exception 'register the account first' using errcode = 'P0002';
  end if;
  insert into public.organizations (slug, name, created_by) values (p_slug, p_name, me) returning id into o;
  insert into public.org_roots (org_id, user_id, account_key) values (o, me, key);
  insert into public.org_members (org_id, user_id, role, scope) values (o, me, 'owner', '{*}');
  perform private.audit(o, 'org.create', p_slug);
  return o;
end $$;

-- Records a membership certificate signed by the caller, who must be an
-- owner, or an admin issuing within their scope and never about owners.
-- The API verifies the signature; clients verify it again.
create or replace function public.add_membership(p_org uuid, p_user uuid, p_role text, p_scope text[],
  p_issued_at_us bigint, p_signature bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare
  me uuid := private.caller();
  my_role text := private.role_in(p_org, me);
  my_scope text[];
  their_role text;
  key bytea;
  s text;
begin
  if my_role not in ('owner', 'admin') then
    raise exception 'only owners and admins manage members' using errcode = '42501';
  end if;
  select account_key into key from public.profiles where user_id = p_user;
  if key is null then
    raise exception 'that user has no EnvRune account yet' using errcode = 'P0002';
  end if;
  select role into their_role from public.org_members where org_id = p_org and user_id = p_user;
  if exists (select 1 from public.org_roots where org_id = p_org and user_id = p_user) then
    raise exception 'root holders cannot be changed' using errcode = '42501';
  end if;
  if my_role = 'admin' then
    if p_role = 'owner' or their_role = 'owner' then
      raise exception 'only owners manage owners' using errcode = '42501';
    end if;
    select scope into my_scope from public.org_members where org_id = p_org and user_id = me;
    foreach s in array p_scope loop
      if not ('*' = any(my_scope) or s = any(my_scope) or
              exists (select 1 from unnest(my_scope) x where x like '%/*' and s like left(x, -1) || '%')) then
        raise exception 'the scope % is outside yours', s using errcode = '42501';
      end if;
    end loop;
  end if;
  insert into public.membership_certs (org_id, user_id, account_key, role, scope, issued_at_us, issuer_id, signature)
  values (p_org, p_user, key, p_role, p_scope, p_issued_at_us, me, p_signature);
  insert into public.org_members (org_id, user_id, role, scope) values (p_org, p_user, p_role, p_scope)
  on conflict (org_id, user_id) do update set role = excluded.role, scope = excluded.scope, updated_at = now();

  if p_role = 'removed' then
    -- Stop serving keys to the removed member now, and start guided rotation
    -- of everything they could read.
    delete from public.wrapped_keys w using public.environments e, public.projects p
    where w.environment_id = e.id and e.project_id = p.id and p.org_id = p_org and w.recipient_user_id = p_user;
    perform private.start_rotation(p_org, 'member removed', p_user, null);
  end if;
  perform private.audit(p_org, 'member.' || p_role, p_user::text, jsonb_build_object('scope', p_scope));
end $$;

-- ---------------------------------------------------------------- projects and environments

create or replace function public.create_project(p_org uuid, p_slug text, p_name text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); id uuid;
begin
  if not private.is_org_admin(p_org, me) then
    raise exception 'only owners and admins create projects' using errcode = '42501';
  end if;
  insert into public.projects (org_id, slug, name) values (p_org, p_slug, p_name) returning projects.id into id;
  perform private.audit(p_org, 'project.create', p_slug);
  return id;
end $$;

create or replace function public.create_environment(p_project uuid, p_slug text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid; id uuid;
begin
  select org_id into o from public.projects where projects.id = p_project;
  if o is null or not private.is_org_admin(o, me) then
    raise exception 'only owners and admins create environments' using errcode = '42501';
  end if;
  insert into public.environments (project_id, slug) values (p_project, p_slug) returning environments.id into id;
  perform private.audit(o, 'environment.create', p_slug);
  return id;
end $$;

-- ---------------------------------------------------------------- keys and values

-- Stores wrapped copies of the current epoch's key, made by a device of the
-- caller. Administrators share with any member or token that may use the
-- environment; any member shares with their own devices, such as a newly
-- approved laptop. Rows are JSON objects with recipient_user_id or
-- recipient_token_id, recipient_id, and base64 wrapped and signature.
create or replace function public.put_wrapped_keys(p_env uuid, p_epoch bigint, p_device text, p_keys jsonb) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; k jsonb; admin boolean;
begin
  select * into info from private.env_info(p_env);
  admin := private.can_administer(p_env, me);
  if not admin and not private.can_use(p_env, me) then
    raise exception 'you cannot share this environment''s key' using errcode = '42501';
  end if;
  if p_epoch <> info.epoch then
    raise exception 'epoch % is not the current one (%)', p_epoch, info.epoch using errcode = '40001';
  end if;
  for k in select * from jsonb_array_elements(p_keys) loop
    if not admin and ((k->>'recipient_user_id') is null or (k->>'recipient_user_id')::uuid <> me) then
      raise exception 'only administrators share keys with others' using errcode = '42501';
    end if;
    if (k->>'recipient_user_id') is not null and not private.can_use(p_env, (k->>'recipient_user_id')::uuid) then
      raise exception 'that member cannot use this environment' using errcode = '42501';
    end if;
    if (k->>'recipient_token_id') is not null and not exists (
        select 1 from public.machine_tokens t where t.id = k->>'recipient_token_id' and t.org_id = info.org_id
          and t.revoked_at is null and private.scope_allows(t.scope, info.project, info.env)) then
      raise exception 'that token cannot use this environment' using errcode = '42501';
    end if;
    insert into public.wrapped_keys (environment_id, epoch, recipient_user_id, recipient_token_id, recipient_id,
      wrapped, wrapper_user_id, wrapper_device_id, signature)
    values (p_env, p_epoch, (k->>'recipient_user_id')::uuid, k->>'recipient_token_id', k->>'recipient_id',
      decode(k->>'wrapped', 'base64'), me, p_device, decode(k->>'signature', 'base64'))
    on conflict (environment_id, epoch, coalesce(recipient_user_id::text, 'token'), recipient_id)
    do update set wrapped = excluded.wrapped, wrapper_user_id = excluded.wrapper_user_id,
      wrapper_device_id = excluded.wrapper_device_id, signature = excluded.signature, created_at = now();
  end loop;
  perform private.audit(info.org_id, 'key.share', info.project || '/' || info.env,
    jsonb_build_object('epoch', p_epoch, 'recipients', jsonb_array_length(p_keys)), p_device);
end $$;

-- Writes the next version of a secret. Versions only go up, one at a time.
create or replace function public.put_secret_version(p_env uuid, p_name text, p_version bigint, p_epoch bigint,
  p_nonce bytea, p_ciphertext bytea, p_device text, p_signature bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; s uuid; current bigint;
begin
  select * into info from private.env_info(p_env);
  if not private.can_administer(p_env, me) then
    raise exception 'you cannot write to this environment' using errcode = '42501';
  end if;
  if p_epoch <> info.epoch then
    raise exception 'epoch % is not the current one (%)', p_epoch, info.epoch using errcode = '40001';
  end if;
  insert into public.secrets (environment_id, name) values (p_env, p_name)
  on conflict (environment_id, name) do nothing;
  select id, current_version into s, current from public.secrets
  where environment_id = p_env and name = p_name for update;
  if p_version <> current + 1 then
    raise exception 'version % is not the next one (%); sync and try again', p_version, current + 1 using errcode = '40001';
  end if;
  insert into public.secret_versions (secret_id, version, epoch, nonce, ciphertext, writer_user_id, writer_device_id, signature)
  values (s, p_version, p_epoch, p_nonce, p_ciphertext, me, p_device, p_signature);
  update public.secrets set current_version = p_version where id = s;
  update public.rotation_items set status = 'rotated', updated_by = me, updated_at = now()
  where secret_id = s and status = 'pending';
  perform private.audit(info.org_id, 'secret.write', info.project || '/' || info.env || '/' || p_name,
    jsonb_build_object('version', p_version), p_device);
end $$;

-- Starts a new epoch: the caller's device uploads the new key wrapped for
-- every remaining recipient, and the current version of every secret
-- re-encrypted under it, in one transaction.
create or replace function public.rotate_environment(p_env uuid, p_new_epoch bigint, p_device text,
  p_keys jsonb, p_versions jsonb) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; v jsonb;
begin
  select * into info from private.env_info(p_env);
  if not private.can_administer(p_env, me) then
    raise exception 'you cannot rotate this environment' using errcode = '42501';
  end if;
  if p_new_epoch <> info.epoch + 1 then
    raise exception 'the next epoch is %', info.epoch + 1 using errcode = '40001';
  end if;
  update public.environments set epoch = p_new_epoch, needs_rotation = false where id = p_env;
  perform public.put_wrapped_keys(p_env, p_new_epoch, p_device, p_keys);
  for v in select * from jsonb_array_elements(p_versions) loop
    perform public.put_secret_version(p_env, v->>'name', (v->>'version')::bigint, p_new_epoch,
      decode(v->>'nonce', 'base64'), decode(v->>'ciphertext', 'base64'), p_device, decode(v->>'signature', 'base64'));
  end loop;
  perform private.audit(info.org_id, 'environment.rotate', info.project || '/' || info.env,
    jsonb_build_object('epoch', p_new_epoch), p_device);
end $$;

-- Everything a member's device needs to read an environment: the wrapped
-- keys for the caller, the newest version of each secret, and the
-- certificates to verify writers and wrappers. Recorded in the audit log.
create or replace function public.fetch_environment(p_env uuid, p_device text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); info record; result jsonb;
begin
  select * into info from private.env_info(p_env);
  if not private.can_use(p_env, me) then
    raise exception 'you cannot use this environment' using errcode = '42501';
  end if;
  if not exists (select 1 from public.devices d where d.user_id = me and d.id = p_device
                 and d.signature is not null and d.revoked_at is null) then
    raise exception 'this device is not approved' using errcode = '42501';
  end if;
  select private.environment_payload(p_env, info.epoch,
    (select coalesce(jsonb_agg(private.wrapped_json(w)), '[]') from public.wrapped_keys w
     where w.environment_id = p_env and w.epoch = info.epoch and w.recipient_user_id = me
       and w.recipient_id in (p_device, 'recovery')))
  into result;
  perform private.audit(info.org_id, 'environment.fetch', info.project || '/' || info.env,
    jsonb_build_object('epoch', info.epoch), p_device);
  return result;
end $$;

create or replace function private.wrapped_json(w public.wrapped_keys) returns jsonb
language sql immutable as $$
  select jsonb_build_object('epoch', w.epoch, 'recipient_user_id', w.recipient_user_id, 'recipient_token_id', w.recipient_token_id,
    'recipient_id', w.recipient_id, 'wrapped', encode(w.wrapped, 'base64'), 'wrapper_user_id', w.wrapper_user_id,
    'wrapper_device_id', w.wrapper_device_id, 'signature', encode(w.signature, 'base64'));
$$;

create or replace function private.environment_payload(p_env uuid, p_epoch bigint, p_wrapped jsonb) returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object(
    'environment_id', p_env,
    'epoch', p_epoch,
    'wrapped_keys', p_wrapped,
    'secrets', (select coalesce(jsonb_agg(jsonb_build_object(
        'name', s.name, 'version', v.version, 'epoch', v.epoch, 'nonce', encode(v.nonce, 'base64'),
        'ciphertext', encode(v.ciphertext, 'base64'), 'writer_user_id', v.writer_user_id,
        'writer_device_id', v.writer_device_id, 'signature', encode(v.signature, 'base64')) order by s.name), '[]')
      from public.secrets s join public.secret_versions v on v.secret_id = s.id and v.version = s.current_version
      where s.environment_id = p_env),
    -- Writers' and wrappers' device certificates, to check signatures.
    'devices', (select coalesce(jsonb_agg(distinct jsonb_build_object(
        'user_id', d.user_id, 'id', d.id, 'kind', d.kind, 'age_recipient', d.age_recipient,
        'signing_key', encode(d.signing_key, 'base64'), 'created_at_us', d.created_at_us,
        'signature', encode(d.signature, 'base64'))), '[]')
      from public.devices d where d.signature is not null and (
        exists (select 1 from public.secrets s join public.secret_versions v on v.secret_id = s.id
                where s.environment_id = p_env and v.writer_user_id = d.user_id and v.writer_device_id = d.id)
        or exists (select 1 from public.wrapped_keys w
                   where w.environment_id = p_env and w.wrapper_user_id = d.user_id and w.wrapper_device_id = d.id))),
    -- The organization's ids and membership certificates, so a machine
    -- token, which has no snapshot, can verify writers and wrappers.
    'ids', (select jsonb_build_object('org_id', p.org_id, 'project_id', p.id)
            from public.environments e join public.projects p on p.id = e.project_id where e.id = p_env),
    'certificates', (select coalesce(jsonb_agg(jsonb_build_object(
        'org_id', c.org_id, 'user_id', c.user_id, 'account_key', encode(c.account_key, 'base64'), 'role', c.role,
        'scope', c.scope, 'issued_at_us', c.issued_at_us, 'issuer_id', c.issuer_id,
        'signature', encode(c.signature, 'base64')) order by c.id), '[]')
      from public.membership_certs c join public.projects p on p.org_id = c.org_id
      join public.environments e on e.project_id = p.id where e.id = p_env));
$$;

-- For the API only, after it checked the token's secret against its hash.
create or replace function public.fetch_environment_for_token(p_token text, p_env uuid) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare t public.machine_tokens; info record; result jsonb;
begin
  select * into t from public.machine_tokens where id = p_token;
  select * into info from private.env_info(p_env);
  if t.id is null or t.revoked_at is not null or t.expires_at < now() or t.org_id <> info.org_id
     or not private.scope_allows(t.scope, info.project, info.env) then
    raise exception 'this token cannot use this environment' using errcode = '42501';
  end if;
  update public.machine_tokens set last_used_at = now() where id = p_token;
  select private.environment_payload(p_env, info.epoch,
    (select coalesce(jsonb_agg(private.wrapped_json(w)), '[]') from public.wrapped_keys w
     where w.environment_id = p_env and w.recipient_token_id = p_token and w.epoch = info.epoch))
  into result;
  insert into public.audit_log (org_id, actor_token_id, action, target, detail, hash)
  values (info.org_id, p_token, 'environment.fetch', info.project || '/' || info.env, jsonb_build_object('epoch', info.epoch), ''::bytea);
  return result;
end $$;
revoke execute on function public.fetch_environment_for_token(text, uuid) from public, anon, authenticated;
grant execute on function public.fetch_environment_for_token(text, uuid) to service_role;

-- ---------------------------------------------------------------- machine tokens

create or replace function public.create_machine_token(p_org uuid, p_id text, p_name text, p_age_recipient text,
  p_scope text[], p_created_at_us bigint, p_signature bytea, p_secret_hash bytea, p_expires_at timestamptz) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  if not private.is_org_admin(p_org, me) then
    raise exception 'only owners and admins create machine tokens' using errcode = '42501';
  end if;
  if p_expires_at > now() + interval '1 year' then
    raise exception 'tokens expire within a year' using errcode = '22023';
  end if;
  insert into public.machine_tokens (id, org_id, created_by, name, age_recipient, scope, created_at_us, signature, secret_hash, expires_at)
  values (p_id, p_org, me, p_name, p_age_recipient, p_scope, p_created_at_us, p_signature, p_secret_hash, p_expires_at);
  perform private.audit(p_org, 'token.create', p_id, jsonb_build_object('scope', p_scope, 'expires_at', p_expires_at));
end $$;

create or replace function public.revoke_machine_token(p_id text) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid;
begin
  select org_id into o from public.machine_tokens where id = p_id;
  if o is null or not private.is_org_admin(o, me) then
    raise exception 'only owners and admins revoke machine tokens' using errcode = '42501';
  end if;
  update public.machine_tokens set revoked_at = now() where id = p_id and revoked_at is null;
  delete from public.wrapped_keys where recipient_token_id = p_id;
  perform private.start_rotation(o, 'machine token revoked', null, p_id);
  perform private.audit(o, 'token.revoke', p_id);
end $$;

-- For the API: the stored hash of a token's secret, to compare in constant time.
create or replace function public.machine_token_secret_hash(p_id text) returns bytea
language sql stable security definer set search_path = '' as $$
  select secret_hash from public.machine_tokens where id = p_id and revoked_at is null and expires_at > now();
$$;
revoke execute on function public.machine_token_secret_hash(text) from public, anon, authenticated;
grant execute on function public.machine_token_secret_hash(text) to service_role;

-- ---------------------------------------------------------------- guided rotation

-- Lists every secret the subject could decrypt: all secrets of the
-- environments they received keys for, and marks those environments for a
-- new epoch.
create or replace function private.start_rotation(p_org uuid, p_reason text, p_user uuid, p_token text) returns void
language plpgsql security definer set search_path = '' as $$
declare task uuid;
begin
  insert into public.rotation_tasks (org_id, reason, subject_user_id, subject_token, created_by)
  values (p_org, p_reason, p_user, p_token, auth.uid()) returning id into task;
  with exposed as (
    select e.id from public.environments e join public.projects p on p.id = e.project_id
    where p.org_id = p_org and exists (
      select 1 from public.audit_log a
      where a.org_id = p_org and a.action = 'environment.fetch' and a.target = p.slug || '/' || e.slug
        and ((p_user is not null and a.actor_user_id = p_user) or (p_token is not null and a.actor_token_id = p_token))))
  , marked as (
    update public.environments set needs_rotation = true where id in (select id from exposed) returning id)
  insert into public.rotation_items (task_id, secret_id)
  select task, s.id from public.secrets s where s.environment_id in (select id from marked);
end $$;

create or replace function public.update_rotation_item(p_task uuid, p_secret uuid, p_status text) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid;
begin
  select org_id into o from public.rotation_tasks where id = p_task;
  if o is null or not private.is_org_admin(o, me) then
    raise exception 'only owners and admins update rotation' using errcode = '42501';
  end if;
  if p_status not in ('pending', 'rotated', 'accepted') then
    raise exception 'unknown status %', p_status using errcode = '22023';
  end if;
  update public.rotation_items set status = p_status, updated_by = me, updated_at = now()
  where task_id = p_task and secret_id = p_secret;
  perform private.audit(o, 'rotation.' || p_status, p_secret::text);
end $$;

-- ---------------------------------------------------------------- grants

revoke execute on all functions in schema private from public, anon, authenticated;
-- RLS policies call these as the querying user. The private schema is not
-- exposed through the API, so users cannot call them directly.
grant usage on schema private to authenticated;
grant execute on function private.is_member(uuid, uuid), private.is_org_admin(uuid, uuid),
  private.role_in(uuid, uuid) to authenticated;
revoke execute on all functions in schema public from anon;
grant execute on function public.fetch_environment_for_token(text, uuid) to service_role;
grant execute on function public.machine_token_secret_hash(text) to service_role;
