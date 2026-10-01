# EnvRune Cloud server

The API the `envrune` CLI calls (`/api/v1`) and the panel, in one Next.js
app. It stores and returns ciphertext, signatures, and metadata through
Supabase; it never sees a secret value or a key that decrypts one. The
design is in [docs/cloud-crypto.md](../../docs/cloud-crypto.md), and the
database schema in [`../supabase`](../supabase).

## Develop

With Docker running:

```sh
(cd .. && npx supabase start)   # local Postgres and sign-in; prints the keys
npm install
npm run dev
```

Put the local Supabase's address and keys in `.env.local`, which Git
ignores:

```sh
NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=<publishable key>
SUPABASE_SECRET_KEY=<secret key>
```

These are read when a request needs them, not inlined by the build
(`src/lib/env.ts`), so one build serves any deployment.

## Check

```sh
npm run lint
npm test          # signing, against vectors shared with the Go client
../e2e.sh         # the CLI's client against this server and the database
```

## Deploy

On Vercel, set the project's root directory to `cloud/web` and the three
variables above. Anywhere else, use the Docker image:
[docs/self-hosting.md](../../docs/self-hosting.md).
