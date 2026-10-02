-- A compromised project. See docs/cloud-operations.md.
--
-- When a project's secrets must be assumed known, its owner takes the keys
-- away from everyone at once: machine tokens that can reach the project are
-- revoked, and every key wrapped for anyone but the device that asks, and
-- that owner's recovery recipient, is deleted. The owner's CLI then starts
-- new epochs wrapped for that device only, and administrators share the new
-- keys again when they are ready. Every secret of the project is listed for
-- rotation. Nobody is removed: memberships are for the owner to review.

create or replace function public.emergency(p_project uuid, p_device text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid; slug text; task uuid; tokens text[]; envs int; listed int;
begin
  select p.org_id, p.slug into o, slug from public.projects p where p.id = p_project;
  if o is null or coalesce(private.role_in(o, me), '') <> 'owner' then
    raise exception 'only an owner declares an emergency' using errcode = '42501';
  end if;
  if not exists (select 1 from public.devices d where d.user_id = me and d.id = p_device
                 and d.signature is not null and d.revoked_at is null) then
    raise exception 'this device is not approved' using errcode = '42501';
  end if;

  with revoked as (
    update public.machine_tokens t set revoked_at = now()
    where t.org_id = o and t.revoked_at is null
      and exists (select 1 from unnest(t.scope) s where s = '*' or s like slug || '/%')
    returning t.id)
  select coalesce(array_agg(id), '{}') into tokens from revoked;
  delete from public.wrapped_keys where recipient_token_id = any(tokens);

  delete from public.wrapped_keys w using public.environments e
  where w.environment_id = e.id and e.project_id = p_project
    and not (w.recipient_user_id = me and w.recipient_id in (p_device, 'recovery'));
  update public.environments set needs_rotation = true where project_id = p_project;
  get diagnostics envs = row_count;

  insert into public.rotation_tasks (org_id, reason, created_by) values (o, 'emergency', me) returning id into task;
  insert into public.rotation_items (task_id, secret_id)
  select task, s.id from public.secrets s join public.environments e on e.id = s.environment_id where e.project_id = p_project;
  get diagnostics listed = row_count;

  perform private.audit(o, 'project.emergency', slug, jsonb_build_object('tokens', tokens, 'secrets', listed), p_device);
  return jsonb_build_object('tokens', tokens, 'environments', envs, 'secrets', listed);
end $$;

revoke execute on function public.emergency(uuid, text) from public, anon;
grant execute on function public.emergency(uuid, text) to authenticated;
