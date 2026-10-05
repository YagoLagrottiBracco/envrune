-- Replacing an account key. See docs/cloud-crypto.md.
--
-- An account key cannot change while an organization trusts it: members
-- hold it inside the membership an administrator signed. So an account is
-- reset only while it is in no organization, after an administrator removed
-- it, and is added again like a new member afterwards. A root holder's key
-- is pinned by every member and never changes.
--
-- The device that resets brings a new account key, a new recovery backup
-- and recipient, and its own new keys, certified by the new account key;
-- the API checked those signatures. Everything of the old key goes: the
-- other devices are revoked, and nothing stays wrapped for the account.

create or replace function public.reset_account(p_account_key bytea, p_recovery_backup bytea,
  p_recovery_recipient text, p_recovery_created_at_us bigint, p_recovery_signature bytea,
  p_device_id text, p_device_name text, p_device_age_recipient text, p_device_signing_key bytea,
  p_device_created_at_us bigint, p_device_signature bytea) returns void
language plpgsql security definer set search_path = '' as $$
declare me uuid := private.caller();
begin
  if not exists (select 1 from public.profiles where user_id = me) then
    raise exception 'this account has no keys yet' using errcode = 'P0002';
  end if;
  if exists (select 1 from public.org_roots where user_id = me) then
    raise exception 'a root holder''s account key is pinned by every member of the organization and cannot be replaced'
      using errcode = '42501';
  end if;
  if exists (select 1 from public.org_members where user_id = me and role <> 'removed') then
    raise exception 'an account is reset only while it is in no organization; ask an owner or admin of each to remove you first'
      using errcode = '42501';
  end if;
  if p_device_signature is null then
    raise exception 'the device must be certified by the new account key' using errcode = '22023';
  end if;
  update public.profiles set account_key = p_account_key, recovery_backup = p_recovery_backup where user_id = me;
  delete from public.wrapped_keys where recipient_user_id = me;
  update public.devices set revoked_at = now() where user_id = me and kind = 'device' and revoked_at is null;
  update public.devices set age_recipient = p_recovery_recipient, created_at_us = p_recovery_created_at_us,
    signature = p_recovery_signature
  where user_id = me and id = 'recovery' and kind = 'recovery';
  insert into public.devices (user_id, id, kind, name, age_recipient, signing_key, created_at_us, signature)
  values (me, p_device_id, 'device', p_device_name, p_device_age_recipient, p_device_signing_key,
    p_device_created_at_us, p_device_signature);
end $$;

create or replace function public.schema_version() returns bigint
language sql immutable set search_path = '' as $$ select 20261005140000::bigint $$;
