-- Access rules of the EnvRune Cloud schema, played out by five users:
-- alice founds the organization, bob is an admin of the shop project, carol
-- a maintainer and dave a consumer of shop/production, and mallory is not a
-- member. Signatures are placeholders: the database does not check them;
-- the API and every client do.
begin;
select plan(46);

insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000000a', 'alice@example.com'),
  ('00000000-0000-0000-0000-00000000000b', 'bob@example.com'),
  ('00000000-0000-0000-0000-00000000000c', 'carol@example.com'),
  ('00000000-0000-0000-0000-00000000000d', 'dave@example.com'),
  ('00000000-0000-0000-0000-00000000000e', 'mallory@example.com');

create function pg_temp.sig() returns bytea language sql as $$ select decode(repeat('ab', 64), 'hex') $$;
create function pg_temp.key(n int) returns bytea language sql as $$ select decode(lpad(to_hex(n), 64, '0'), 'hex') $$;
create function pg_temp.become(u text) returns void language sql as $$
  select set_config('request.jwt.claims', json_build_object('sub', u, 'role', 'authenticated')::text, true);
$$;

-- Everyone registers an account and one approved device.
set local role authenticated;
select pg_temp.become('00000000-0000-0000-0000-00000000000a');
select public.register_account(pg_temp.key(1), 'backup', 'age1alicerecovery', 1, pg_temp.sig());
select public.register_device('alice-laptop', 'laptop', 'age1alice', pg_temp.key(11), 1, pg_temp.sig());
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select public.register_account(pg_temp.key(2), 'backup', 'age1bobrecovery', 1, pg_temp.sig());
select pg_temp.become('00000000-0000-0000-0000-00000000000c');
select public.register_account(pg_temp.key(3), 'backup', 'age1carolrecovery', 1, pg_temp.sig());
select public.register_device('carol-laptop', 'laptop', 'age1carol', pg_temp.key(13), 1, pg_temp.sig());
select pg_temp.become('00000000-0000-0000-0000-00000000000d');
select public.register_account(pg_temp.key(4), 'backup', 'age1daverecovery', 1, pg_temp.sig());
select public.register_device('dave-laptop', 'laptop', 'age1dave', pg_temp.key(14), 1, null);
select pg_temp.become('00000000-0000-0000-0000-00000000000e');
select public.register_account(pg_temp.key(5), 'backup', 'age1mallory', 1, pg_temp.sig());

select throws_ok($$ select public.register_account(pg_temp.key(5), 'again', 'age1x', 1, pg_temp.sig()) $$,
  '23505', null, 'an account registers only once');

-- alice founds acme with a shop project and a production environment.
select pg_temp.become('00000000-0000-0000-0000-00000000000a');
select public.create_organization('acme', 'Acme') as org \gset
select public.create_project(:'org', 'shop', 'Shop') as project \gset
select public.create_environment(:'project', 'production') as env \gset
select public.create_environment(:'project', 'staging') as staging \gset
select is((select role from public.org_members where user_id = auth.uid()), 'owner', 'the founder is an owner');
select is((select count(*)::int from public.org_roots where org_id = :'org'), 1, 'the founder is the root');

select public.add_membership(:'org', '00000000-0000-0000-0000-00000000000b', 'admin', '{shop/*}', 1, pg_temp.sig());

-- Up to two more accounts hold the root, named when the organization is
-- founded; they are owners nobody can change.
select public.create_organization('trio', 'Trio', array['00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000c']::uuid[]) as trio \gset
select is((select count(*)::int from public.org_roots where org_id = :'trio'), 3, 'an organization may have two more root holders');
select is((select role from public.org_members where org_id = :'trio' and user_id = '00000000-0000-0000-0000-00000000000c'), 'owner',
  'a root holder is an owner');
select throws_ok($$ select public.create_organization('quartet', 'Quartet', array['00000000-0000-0000-0000-00000000000b',
  '00000000-0000-0000-0000-00000000000c', '00000000-0000-0000-0000-00000000000d']::uuid[]) $$, '22023', null, 'never more than two');
select throws_ok(format($$ select public.add_membership(%L, '00000000-0000-0000-0000-00000000000c', 'removed', '{*}', 9, pg_temp.sig()) $$, :'trio'),
  '42501', null, 'not even the founder removes a root holder');

-- bob manages members within his scope only.
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select lives_ok(format($$ select public.add_membership(%L, '00000000-0000-0000-0000-00000000000c', 'maintainer', '{shop/production}', 2, pg_temp.sig()) $$, :'org'),
  'an admin adds a maintainer in scope');
select lives_ok(format($$ select public.add_membership(%L, '00000000-0000-0000-0000-00000000000d', 'consumer', '{shop/production}', 3, pg_temp.sig()) $$, :'org'),
  'an admin adds a consumer in scope');
select throws_ok(format($$ select public.add_membership(%L, '00000000-0000-0000-0000-00000000000e', 'owner', '{*}', 4, pg_temp.sig()) $$, :'org'),
  '42501', null, 'an admin cannot make an owner');
select throws_ok(format($$ select public.add_membership(%L, '00000000-0000-0000-0000-00000000000e', 'consumer', '{billing/*}', 4, pg_temp.sig()) $$, :'org'),
  '42501', null, 'an admin cannot grant outside their scope');
select throws_ok(format($$ select public.add_membership(%L, '00000000-0000-0000-0000-00000000000a', 'removed', '{*}', 4, pg_temp.sig()) $$, :'org'),
  '42501', null, 'nobody changes a root holder');

-- mallory sees nothing and can do nothing.
select pg_temp.become('00000000-0000-0000-0000-00000000000e');
select is((select count(*)::int from public.organizations), 0, 'a non-member sees no organization');
select is((select count(*)::int from public.projects), 0, 'a non-member sees no project');
select throws_ok(format($$ select public.create_project(%L, 'evil', 'Evil') $$, :'org'), '42501', null,
  'a non-member cannot create a project');
select throws_ok(format($$ select public.fetch_environment(%L, 'x') $$, :'env'), '42501', null,
  'a non-member cannot fetch an environment');
select throws_ok($$ insert into public.organizations (slug, name, created_by) values ('x', 'x', auth.uid()) $$,
  '42501', null, 'nobody writes tables directly');

-- carol writes values; versions only go up by one.
select pg_temp.become('00000000-0000-0000-0000-00000000000c');
select lives_ok(format($$ select public.put_secret_version(%L, 'stripe-key', 1, 1, decode(repeat('00', 24), 'hex'), 'ciphertext', 'carol-laptop', pg_temp.sig()) $$, :'env'),
  'a maintainer writes version 1');
select throws_ok(format($$ select public.put_secret_version(%L, 'stripe-key', 1, 1, decode(repeat('00', 24), 'hex'), 'x', 'carol-laptop', pg_temp.sig()) $$, :'env'),
  '40001', null, 'a version cannot be written twice');
select throws_ok(format($$ select public.put_secret_version(%L, 'stripe-key', 3, 1, decode(repeat('00', 24), 'hex'), 'x', 'carol-laptop', pg_temp.sig()) $$, :'env'),
  '40001', null, 'versions cannot skip');
select throws_ok(format($$ select public.put_secret_version(%L, 'stripe-key', 1, 1, decode(repeat('00', 24), 'hex'), 'x', 'carol-laptop', pg_temp.sig()) $$, :'staging'),
  '42501', null, 'a maintainer cannot write outside their scope');
select throws_ok($$ select * from public.secret_versions $$, '42501', null, 'ciphertext is not readable directly');
select throws_ok($$ select * from public.wrapped_keys $$, '42501', null, 'wrapped keys are not readable directly');
select lives_ok(format($$ select public.put_wrapped_keys(%L, 1, 'carol-laptop', jsonb_build_array(
    jsonb_build_object('recipient_user_id', '00000000-0000-0000-0000-00000000000d', 'recipient_id', 'dave-laptop',
      'wrapped', encode('wrapped-for-dave', 'base64'), 'signature', encode(pg_temp.sig(), 'base64')))) $$, :'env'),
  'a maintainer shares the key with a consumer');
select throws_ok(format($$ select public.put_wrapped_keys(%L, 1, 'carol-laptop', jsonb_build_array(
    jsonb_build_object('recipient_user_id', '00000000-0000-0000-0000-00000000000e', 'recipient_id', 'mallory-laptop',
      'wrapped', encode('x', 'base64'), 'signature', encode(pg_temp.sig(), 'base64')))) $$, :'env'),
  '42501', null, 'the key cannot be shared with a non-member');

-- dave reads, but only from an approved device, and cannot write.
select pg_temp.become('00000000-0000-0000-0000-00000000000d');
select throws_ok(format($$ select public.fetch_environment(%L, 'dave-laptop') $$, :'env'), '42501', null,
  'a pending device cannot fetch');
select public.approve_device('dave-laptop', 2, pg_temp.sig(), null);
select is(jsonb_array_length(public.fetch_environment(:'env', 'dave-laptop')->'secrets'), 1, 'a consumer fetches the values');
select is(jsonb_array_length(public.fetch_environment(:'env', 'dave-laptop')->'wrapped_keys'), 1, 'a consumer gets their wrapped key');
select throws_ok(format($$ select public.put_secret_version(%L, 'stripe-key', 2, 1, decode(repeat('00', 24), 'hex'), 'x', 'dave-laptop', pg_temp.sig()) $$, :'env'),
  '42501', null, 'a consumer cannot write');
select lives_ok(format($$ select public.put_wrapped_keys(%L, 1, 'dave-laptop', jsonb_build_array(
    jsonb_build_object('recipient_user_id', '00000000-0000-0000-0000-00000000000d', 'recipient_id', 'dave-desktop',
      'wrapped', encode('x', 'base64'), 'signature', encode(pg_temp.sig(), 'base64')))) $$, :'env'),
  'a consumer shares the key with their own new device');
select throws_ok(format($$ select public.put_wrapped_keys(%L, 1, 'dave-laptop', jsonb_build_array(
    jsonb_build_object('recipient_user_id', '00000000-0000-0000-0000-00000000000c', 'recipient_id', 'carol-laptop',
      'wrapped', encode('x', 'base64'), 'signature', encode(pg_temp.sig(), 'base64')))) $$, :'env'),
  '42501', null, 'a consumer cannot share the key with someone else');

-- bob removes dave: no more keys for dave, and guided rotation starts.
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select public.add_membership(:'org', '00000000-0000-0000-0000-00000000000d', 'removed', '{shop/production}', 5, pg_temp.sig());
reset role;
select is((select count(*)::int from public.wrapped_keys where recipient_user_id = '00000000-0000-0000-0000-00000000000d'), 0,
  'a removed member keeps no wrapped keys');
select is((select count(*)::int from public.rotation_items where task_id in (select id from public.rotation_tasks where org_id = :'org')), 1, 'rotation lists the secret the removed member fetched');
select ok((select needs_rotation from public.environments where id = :'env'), 'the environment needs a new epoch');
set local role authenticated;
select pg_temp.become('00000000-0000-0000-0000-00000000000d');
select throws_ok(format($$ select public.fetch_environment(%L, 'dave-laptop') $$, :'env'), '42501', null,
  'a removed member cannot fetch');

-- The new epoch encrypts the same values again, which dave already knows:
-- that is not a rotation. Only a new value is.
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select public.rotate_environment(:'env', 2, 'bob-laptop', '[]'::jsonb, jsonb_build_array(jsonb_build_object(
  'name', 'stripe-key', 'version', (select current_version + 1 from public.secrets where environment_id = :'env' and name = 'stripe-key'),
  'nonce', encode(decode(repeat('00', 24), 'hex'), 'base64'), 'ciphertext', encode('y', 'base64'), 'signature', encode(pg_temp.sig(), 'base64'))));
reset role;
select is((select status from public.rotation_items where task_id in (select id from public.rotation_tasks where org_id = :'org')), 'pending', 'a new epoch does not count as rotating the values');
set local role authenticated;
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select public.put_secret_version(:'env', 'stripe-key', (select current_version + 1 from public.secrets where environment_id = :'env' and name = 'stripe-key'),
  2, decode(repeat('00', 24), 'hex'), 'z', 'bob-laptop', pg_temp.sig());
reset role;
select is((select status from public.rotation_items where task_id in (select id from public.rotation_tasks where org_id = :'org')), 'rotated', 'a new value rotates the secret');

-- Keeping a value as it is goes on the record, and only owners and admins
-- decide it.
select t.id as task, i.secret_id as secret from public.rotation_tasks t join public.rotation_items i on i.task_id = t.id
where t.org_id = :'org' \gset
set local role authenticated;
select pg_temp.become('00000000-0000-0000-0000-00000000000c');
select throws_ok(format($$ select public.update_rotation_item(%L, %L, 'accepted') $$, :'task', :'secret'), '42501', null,
  'a maintainer cannot accept a rotation');
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select public.update_rotation_item(:'task', :'secret', 'accepted');
reset role;
select is((select status from public.rotation_items where task_id = :'task'), 'accepted', 'an admin records that a value stays');
select is((select count(*)::int from public.audit_log where org_id = :'org' and action = 'secret.reencrypt'), 1,
  'the audit log tells a value encrypted again from a new one');
set local role authenticated;

-- Owners and admins set how long devices may stay offline.
select pg_temp.become('00000000-0000-0000-0000-00000000000c');
select throws_ok(format($$ select public.set_offline_days(%L, 30) $$, :'org'), '42501', null, 'a maintainer cannot set the offline limit');
select pg_temp.become('00000000-0000-0000-0000-00000000000b');
select public.set_offline_days(:'org', 30);
select is((select offline_days from public.organizations where id = :'org'), 30, 'an admin sets the offline limit');
select throws_ok(format($$ select public.set_offline_days(%L, 0) $$, :'org'), '22023', null, 'the offline limit is at least a day');

-- The audit log is append-only and hash-chained.
reset role;
select ok((select count(*) from public.audit_log where action = 'environment.fetch' and actor_user_id = '00000000-0000-0000-0000-00000000000d') = 2,
  'every fetch is recorded');
select throws_ok($$ update public.audit_log set action = 'nothing' $$, 'P0001', 'the audit log is append-only', 'the audit log cannot be edited');
select is((select count(*)::int from (
    select hash, lead(prev_hash) over (order by id) as next_prev from public.audit_log where org_id = :'org') c
  where next_prev is not null and next_prev <> hash), 0, 'each entry chains to the previous one');

select * from finish();
rollback;
