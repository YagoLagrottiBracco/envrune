-- Replacing a recovery key. See docs/cloud-crypto.md.
--
-- One of the caller's devices made a new recovery key, encrypted a new
-- backup with it, and signed a new recovery recipient with the account key;
-- the API checked that signature. Nothing may stay that the old recovery
-- identity opens, so the keys wrapped for the old recipient go. The device
-- wraps the current ones for the new recipient next.

create or replace function public.reset_recovery(p_recovery_backup bytea, p_recovery_recipient text,
  p_recovery_created_at_us bigint, p_recovery_signature bytea, p_device text) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller(); o uuid;
begin
  if not exists (select 1 from public.devices where user_id = me and id = p_device and kind = 'device'
      and signature is not null and revoked_at is null) then
    raise exception 'only one of your approved devices replaces the recovery key' using errcode = '42501';
  end if;
  update public.profiles set recovery_backup = p_recovery_backup where user_id = me;
  if not found then
    raise exception 'this account has no keys yet' using errcode = 'P0002';
  end if;
  update public.devices set age_recipient = p_recovery_recipient, created_at_us = p_recovery_created_at_us,
    signature = p_recovery_signature
  where user_id = me and id = 'recovery' and kind = 'recovery';
  delete from public.wrapped_keys where recipient_user_id = me and recipient_id = 'recovery';
  for o in select m.org_id from public.org_members m where m.user_id = me and m.role <> 'removed' loop
    perform private.audit(o, 'recovery.reset', 'recovery', '{}', p_device);
  end loop;
end $$;
