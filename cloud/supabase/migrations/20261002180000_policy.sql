-- Rules about who may fetch. See docs/cloud-operations.md.
--
-- An organization may deny roles an environment, whatever scope a member
-- was given: "consumers never in production", or "people never fetch this
-- one; machine tokens do". Rules only take away, never apply to machine
-- tokens, which have scopes of their own, and never to owners, who must
-- keep an environment manageable.

create table public.org_policies (
  org_id     uuid primary key references public.organizations on delete cascade,
  rules      jsonb not null default '[]',
  updated_by uuid references auth.users,
  updated_at timestamptz not null default now()
);
alter table public.org_policies enable row level security;
create policy "member reads rules" on public.org_policies for select to authenticated
  using (private.is_member(org_id, auth.uid()));
revoke insert, update, delete, truncate on public.org_policies from anon, authenticated;

-- Whether a rule of the organization denies this role this environment.
create or replace function private.policy_denies(p_org uuid, p_role text, p_project text, p_env text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.org_policies o, jsonb_array_elements(o.rules) r
    where o.org_id = p_org
      and (r->'deny') ? p_role
      and split_part(r->>'environments', '/', 1) in ('*', p_project)
      and split_part(r->>'environments', '/', 2) in ('*', p_env));
$$;

-- Both checks now also ask the rules. Everything that serves ciphertext,
-- keys, or the use of a sensitive secret goes through one of them.
create or replace function private.can_use(p_env uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.environments e join public.projects p on p.id = e.project_id
    join public.org_members m on m.org_id = p.org_id and m.user_id = p_user
    where e.id = p_env and (
      m.role = 'owner' or
      (m.role in ('admin', 'maintainer', 'consumer') and private.scope_allows(m.scope, p.slug, e.slug)
        and not private.policy_denies(p.org_id, m.role, p.slug, e.slug))));
$$;

create or replace function private.can_administer(p_env uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.environments e join public.projects p on p.id = e.project_id
    join public.org_members m on m.org_id = p.org_id and m.user_id = p_user
    where e.id = p_env and (
      m.role = 'owner' or
      (m.role in ('admin', 'maintainer') and private.scope_allows(m.scope, p.slug, e.slug)
        and not private.policy_denies(p.org_id, m.role, p.slug, e.slug))));
$$;

-- Replaces the organization's rules. p_rules is a JSON array of objects with
-- environments ("project/environment", either side may be *) and deny (roles).
create or replace function public.set_policy(p_org uuid, p_rules jsonb) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); r jsonb; role text;
begin
  if coalesce(private.role_in(p_org, me), '') <> 'owner' then
    raise exception 'only owners set the organization''s rules' using errcode = '42501';
  end if;
  if jsonb_typeof(p_rules) <> 'array' or jsonb_array_length(p_rules) > 100 then
    raise exception 'rules are a list of at most 100' using errcode = '22023';
  end if;
  for r in select * from jsonb_array_elements(p_rules) loop
    if jsonb_typeof(r) <> 'object' or coalesce(r->>'environments', '') !~ '^(\*|[a-z][a-z0-9-]{0,62})/(\*|[a-z][a-z0-9_.-]{0,62})$' then
      raise exception 'a rule names environments as project/environment, where either side may be *' using errcode = '22023';
    end if;
    if jsonb_typeof(r->'deny') <> 'array' or jsonb_array_length(r->'deny') = 0 then
      raise exception 'a rule denies at least one role' using errcode = '22023';
    end if;
    for role in select jsonb_array_elements_text(r->'deny') loop
      if role not in ('admin', 'maintainer', 'consumer') then
        raise exception 'a rule can deny admin, maintainer, or consumer; % is not one of them', role using errcode = '22023';
      end if;
    end loop;
  end loop;
  insert into public.org_policies (org_id, rules, updated_by) values (p_org, p_rules, me)
  on conflict (org_id) do update set rules = excluded.rules, updated_by = me, updated_at = now();
  perform private.audit(p_org, 'policy.set', '', jsonb_build_object('rules', jsonb_array_length(p_rules)));
end $$;

revoke execute on function private.policy_denies(uuid, text, text, text) from public, anon, authenticated;
revoke execute on function public.set_policy(uuid, jsonb) from public, anon;
grant execute on function public.set_policy(uuid, jsonb) to authenticated;
