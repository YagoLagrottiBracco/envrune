# Self-hosting EnvRune Cloud

EnvRune Cloud can run on your own infrastructure. This guide sets it up
with Docker. For what the server is and how members use it, see
[cloud.md](cloud.md); for what it can and cannot see,
[cloud-crypto.md](cloud-crypto.md).

Whoever runs the server is in the same position as any EnvRune Cloud
server: it stores ciphertext, names, and the audit log, and **cannot read a
secret value**. Values are encrypted and decrypted by the `envrune` CLI on
each member's device.

## What you run

| Piece | What it is | Where it comes from |
| --- | --- | --- |
| EnvRune Cloud server | The API the CLI calls, and the panel. One Node.js container, no state. | `cloud/web` in this repository |
| Supabase | Postgres, sign-in by email, and the gateway the server queries through. Holds all the data. | [Self-hosted with Docker](https://supabase.com/docs/guides/self-hosting/docker), or a hosted Supabase project |

The CLI talks only to the EnvRune Cloud server. Browsers talk to the server
and, to sign in, to Supabase.

You need two HTTPS addresses, for example `https://envrune.example.com` for
the server and `https://supabase.example.com` for Supabase, and a way to
send email, since members sign in with a link sent to their address.

## 1. Supabase

Use a hosted project, or follow Supabase's
[self-hosting guide](https://supabase.com/docs/guides/self-hosting/docker).
Either way, set these; in a hosted project they are under Authentication,
and in a self-hosted one they are in Supabase's own `.env`:

| Setting | Value |
| --- | --- |
| Site URL (`SITE_URL`) | `https://envrune.example.com` |
| Redirect URLs (`ADDITIONAL_REDIRECT_URLS`) | `https://envrune.example.com/**` |
| Email (`SMTP_*`) | your mail server, so sign-in links arrive |
| Public address (`API_EXTERNAL_URL`, `SUPABASE_PUBLIC_URL`; self-hosted only) | `https://supabase.example.com` |

Replace every default password and key of a self-hosted Supabase before
exposing it, as its guide says.

EnvRune Cloud uses the database, the sign-in service, and the REST gateway.
Supabase's storage, realtime, and edge functions are not used and can stay
off.

## 2. The database schema

The schema is in `cloud/supabase/migrations`. Apply every file, in the
order of the names, to the Supabase database:

```sh
git clone https://github.com/YagoLagrottiBracco/envrune && cd envrune
for file in cloud/supabase/migrations/*.sql; do
  psql "postgresql://postgres:<password>@<database-host>:5432/postgres" -v ON_ERROR_STOP=1 -f "$file"
done
```

For a hosted project, `npx supabase link` and `npx supabase db push` from
the `cloud` folder do the same.

The schema gives signed-in users no write access to any table: every write
goes through a function that checks the caller's role and records the
change in the audit log. `cloud/supabase/tests` holds the tests of those
rules (`npx supabase test db`).

## 3. The server

```sh
cd cloud
cp .env.example .env    # then fill it in
docker compose up -d --build
```

`.env` holds three values:

| Variable | Value |
| --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase's public address, as browsers and the server reach it |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Supabase's public key: the publishable key of a hosted project, or `ANON_KEY` of a self-hosted one |
| `SUPABASE_SECRET_KEY` | Supabase's server key: the secret key of a hosted project, or `SERVICE_ROLE_KEY` of a self-hosted one |

The first two are sent to browsers. **`SUPABASE_SECRET_KEY` bypasses the
database's access rules**: keep it out of version control and logs. The
server uses it only to hand a signed-in user's session to the CLI and to
check machine tokens. It does not decrypt anything: with it, someone can
read and change ciphertext and metadata, which the CLI's signature checks
then refuse.

The image holds no configuration; the container reads these when it starts,
so one image serves any deployment. To run it without Compose:

```sh
docker build -t envrune-cloud cloud/web
docker run -d -p 127.0.0.1:3000:3000 --env-file cloud/.env envrune-cloud
```

`GET /api/v1/health` answers `{"service":"envrune-cloud","api":1}` when the
server is up; the image's health check uses it.

## 4. HTTPS

The container listens on `127.0.0.1:3000`. Put a reverse proxy with a
certificate in front of it. With [Caddy](https://caddyserver.com), which
gets the certificate by itself:

```text
envrune.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

The CLI refuses a server address that is not `https://`, except on
`localhost`, where plain HTTP is accepted for trying things out.

## 5. Use it

Each member points the CLI at your server once:

```sh
envrune login --server https://envrune.example.com
envrune cloud init
```

or sets `ENVRUNE_CLOUD_SERVER`, which CI jobs need next to `ENVRUNE_TOKEN`.
From here on, [cloud.md](cloud.md) applies unchanged.

Anyone who can reach the sign-in page can create an account, but an account
is in no organization and sees nothing until an owner or admin adds it. To
close sign-up, restrict who can reach the server, or turn sign-ups off in
Supabase after your members have their accounts.

## Running it

- **Back up the Postgres database.** It holds everything: ciphertext, the
  keys wrapped for each device, certificates, and the audit log. The server
  container has no state. A lost database is not recoverable from the
  server; members keep only the last copy each device synced.
- **A backup is not readable by itself.** Restoring one elsewhere gives
  ciphertext. It is still worth protecting: it shows names, membership, and
  activity.
- **Export the audit log regularly** (`envrune cloud audit export`) and keep
  the files outside the server, so a change to the log can be found. See
  [cloud.md](cloud.md#audit-log).
- **Upgrading.** Rebuild the image from the new version and apply any new
  files in `cloud/supabase/migrations`. Until the first release, the first
  migration may still change in place: upgrading a pre-release server means
  starting from an empty database.

## What self-hosting does not change

The limits in [cloud-crypto.md](cloud-crypto.md#what-a-compromised-server-can-and-cannot-do)
hold for your server as for any other: it sees names and activity, can
refuse service, and can serve stale data to a device that has not seen
newer versions. It cannot read values, add a recipient no admin signed, or
serve an older value to a device that has seen a newer one.
