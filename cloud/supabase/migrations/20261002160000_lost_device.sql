-- A lost device. See docs/cloud-operations.md.
--
-- Revoking a device already stopped serving it and deleted its wrapped keys.
-- Whoever has the device may also know every value it fetched, so revoking
-- now opens a guided rotation for those secrets, as removing a member does.

alter table public.rotation_tasks add column subject_device text;

create or replace function public.revoke_device(p_id text) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid; task uuid;
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
    -- Every secret of the environments this device fetched, in this organization.
    if exists (
        select 1 from public.secrets s join public.environments e on e.id = s.environment_id join public.projects p on p.id = e.project_id
        where p.org_id = o and exists (
          select 1 from public.audit_log a
          where a.org_id = o and a.action = 'environment.fetch' and a.target = p.slug || '/' || e.slug
            and a.actor_user_id = me and a.actor_device_id = p_id)) then
      insert into public.rotation_tasks (org_id, reason, subject_user_id, subject_device, created_by)
      values (o, 'device revoked', me, p_id, me) returning id into task;
      insert into public.rotation_items (task_id, secret_id)
      select task, s.id from public.secrets s join public.environments e on e.id = s.environment_id join public.projects p on p.id = e.project_id
      where p.org_id = o and exists (
        select 1 from public.audit_log a
        where a.org_id = o and a.action = 'environment.fetch' and a.target = p.slug || '/' || e.slug
          and a.actor_user_id = me and a.actor_device_id = p_id);
    end if;
  end loop;
end $$;
