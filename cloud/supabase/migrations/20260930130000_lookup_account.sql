-- An admin's CLI needs a new member's account key to sign their membership.
-- This returns only public data, for accounts that registered one, to any
-- signed-in user. The CLI shows the key's fingerprint and asks the admin to
-- compare it with the new member out of band: a server that answered with a
-- key of its own would be caught there (see docs/cloud-crypto.md).
create or replace function public.lookup_account(p_email text) returns table (user_id uuid, account_key text)
language sql stable security definer set search_path = '' as $$
  select p.user_id, encode(p.account_key, 'base64')
  from auth.users u join public.profiles p on p.user_id = u.id
  where private.caller() is not null and lower(u.email) = lower(p_email);
$$;
revoke execute on function public.lookup_account(text) from public, anon;
grant execute on function public.lookup_account(text) to authenticated;

-- The same by user id, base64, for checking a membership certificate.
create or replace function public.lookup_account_by_id(p_user uuid) returns text
language sql stable security definer set search_path = '' as $$
  select encode(p.account_key, 'base64') from public.profiles p
  where private.caller() is not null and p.user_id = p_user;
$$;
revoke execute on function public.lookup_account_by_id(uuid) from public, anon;
grant execute on function public.lookup_account_by_id(uuid) to authenticated;
