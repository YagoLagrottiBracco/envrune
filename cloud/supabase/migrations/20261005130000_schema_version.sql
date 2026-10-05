-- Which schema this database has: the name of the newest migration applied.
-- The server compares it with the one its own version needs, so a database
-- that is behind is called that, by /api/v1/health and `envrune cloud
-- doctor`, before a request fails on what is missing.
--
-- Every later migration redefines this function with its own number; a
-- test in cloud/web keeps the two together.

create or replace function public.schema_version() returns bigint
language sql immutable set search_path = '' as $$ select 20261005130000::bigint $$;

grant execute on function public.schema_version() to anon, authenticated;
