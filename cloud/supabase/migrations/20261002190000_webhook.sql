-- Notifications. See docs/cloud-operations.md.
--
-- An organization may name one HTTPS address to be told about what happens.
-- Events are the audit log's entries, except the frequent ones, so they hold
-- names and never a value. The database only queues them; the server sends
-- them, signing each body with the organization's webhook secret, which is a
-- secret of the server's side, not one of the team's.

create table public.org_webhooks (
  org_id            uuid primary key references public.organizations on delete cascade,
  url               text not null check (url ~ '^https?://' and length(url) <= 2000),
  secret            bytea not null check (length(secret) = 32),
  created_by        uuid not null references auth.users,
  created_at        timestamptz not null default now(),
  failures          integer not null default 0, -- in a row, since the last delivery
  last_error        text,
  last_delivered_at timestamptz
);

create table public.webhook_outbox (
  id           bigint generated always as identity primary key,
  org_id       uuid not null references public.organizations on delete cascade,
  payload      jsonb not null,
  attempts     integer not null default 0,
  delivered_at timestamptz,
  created_at   timestamptz not null default now()
);
create index on public.webhook_outbox (id) where delivered_at is null;

-- No policies: members reach both only through the functions below, which
-- never return the secret, and the server through its own.
alter table public.org_webhooks enable row level security;
alter table public.webhook_outbox enable row level security;
revoke all on public.org_webhooks, public.webhook_outbox from anon, authenticated;

-- Queues an audit entry for the organization's webhook. Fetches, reported
-- use, and forwarded requests are left out: they happen all the time.
create or replace function private.webhook_enqueue() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.action in ('environment.fetch', 'secret.use', 'secret.forward')
     or not exists (select 1 from public.org_webhooks w where w.org_id = new.org_id) then
    return new;
  end if;
  insert into public.webhook_outbox (org_id, payload)
  values (new.org_id, jsonb_build_object(
    'id', new.id, 'organization', (select slug from public.organizations where id = new.org_id),
    'action', new.action, 'target', new.target, 'at', new.at,
    'actor_user_id', new.actor_user_id, 'actor_device_id', new.actor_device_id, 'actor_token_id', new.actor_token_id,
    'detail', new.detail));
  return new;
end $$;
create trigger webhook_enqueue after insert on public.audit_log
  for each row execute function private.webhook_enqueue();

-- Sets the address events are sent to, and the secret their signature uses,
-- which the caller's CLI made and shows once.
create or replace function public.set_webhook(p_org uuid, p_url text, p_secret bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  if not private.is_org_admin(p_org, me) then
    raise exception 'only owners and admins set the webhook' using errcode = '42501';
  end if;
  insert into public.org_webhooks (org_id, url, secret, created_by) values (p_org, p_url, p_secret, me)
  on conflict (org_id) do update set url = excluded.url, secret = excluded.secret, created_by = me, created_at = now(),
    failures = 0, last_error = null;
  perform private.audit(p_org, 'webhook.set', split_part(split_part(p_url, '://', 2), '/', 1));
end $$;

create or replace function public.clear_webhook(p_org uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  if not private.is_org_admin(p_org, me) then
    raise exception 'only owners and admins set the webhook' using errcode = '42501';
  end if;
  delete from public.org_webhooks where org_id = p_org;
  delete from public.webhook_outbox where org_id = p_org and delivered_at is null;
  perform private.audit(p_org, 'webhook.clear', '');
end $$;

-- The webhook as owners, admins, and auditors see it: never its secret.
create or replace function public.webhook_status(p_org uuid) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if coalesce(private.role_in(p_org, private.caller()) in ('owner', 'admin', 'auditor'), false) is not true then
    raise exception 'only owners, admins, and auditors see the webhook' using errcode = '42501';
  end if;
  return (select jsonb_build_object('url', w.url, 'failures', w.failures, 'last_error', w.last_error,
      'last_delivered_at', w.last_delivered_at,
      'waiting', (select count(*) from public.webhook_outbox o where o.org_id = p_org and o.delivered_at is null and o.attempts < 8))
    from public.org_webhooks w where w.org_id = p_org);
end $$;

-- For the server: events still to send, oldest first, with where and how to
-- sign. An event is given up after eight attempts.
create or replace function public.webhook_pending(p_limit integer) returns jsonb
language sql security definer set search_path = '' as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', o.id, 'payload', o.payload, 'url', w.url, 'secret', encode(w.secret, 'base64')) order by o.id), '[]')
  from (select * from public.webhook_outbox where delivered_at is null and attempts < 8 order by id limit p_limit) o
  join public.org_webhooks w on w.org_id = o.org_id;
$$;

-- For the server: what became of one attempt.
create or replace function public.webhook_attempted(p_id bigint, p_ok boolean, p_error text) returns void
language plpgsql security definer set search_path = '' as $$
declare o uuid;
begin
  update public.webhook_outbox set attempts = attempts + 1, delivered_at = case when p_ok then now() end
  where id = p_id returning org_id into o;
  if p_ok then
    update public.org_webhooks set failures = 0, last_error = null, last_delivered_at = now() where org_id = o;
  else
    update public.org_webhooks set failures = failures + 1, last_error = left(p_error, 200) where org_id = o;
  end if;
end $$;

revoke execute on function private.webhook_enqueue() from public, anon, authenticated;
revoke execute on function public.set_webhook(uuid, text, bytea), public.clear_webhook(uuid), public.webhook_status(uuid) from public, anon;
grant execute on function public.set_webhook(uuid, text, bytea), public.clear_webhook(uuid), public.webhook_status(uuid) to authenticated;
revoke execute on function public.webhook_pending(integer), public.webhook_attempted(bigint, boolean, text) from public, anon, authenticated;
grant execute on function public.webhook_pending(integer), public.webhook_attempted(bigint, boolean, text) to service_role;
