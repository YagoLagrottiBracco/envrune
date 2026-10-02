#!/usr/bin/env bash
# End-to-end test of EnvRune Cloud: the CLI's client (internal/cloud)
# against the API (cloud/web) and the database (cloud/supabase), all on this
# machine. Needs Docker, Node, and Go. Usage: cloud/e2e.sh
set -euo pipefail
cd "$(dirname "$0")"

supabase() {
  if type -P supabase >/dev/null; then command supabase "$@"; else npx --yes supabase "$@"; fi
}

# Only the services the API uses: Postgres, Auth, and the REST gateway.
supabase start -x studio,imgproxy,storage-api,realtime,edge-runtime,logflare,vector,supavisor,postgres-meta >/dev/null
eval "$(supabase status -o env | grep -E '^(API_URL|PUBLISHABLE_KEY|SECRET_KEY)=')"

port="${ENVRUNE_E2E_PORT:-3000}"
cd web
[ -d node_modules ] || npm ci
export NEXT_PUBLIC_SUPABASE_URL="$API_URL" NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY="$PUBLISHABLE_KEY" SUPABASE_SECRET_KEY="$SECRET_KEY"
# A proxy identity for this run, so sensitive secrets are tested too.
ENVRUNE_PROXY_IDENTITY="$(node -e 'import("age-encryption").then((age) => age.generateIdentity()).then(console.log)')"
export ENVRUNE_PROXY_IDENTITY
node node_modules/next/dist/bin/next build >/dev/null
# The server the Docker image runs: the standalone build with its assets.
cp -r public .next/standalone/
cp -r .next/static .next/standalone/.next/
log="$(mktemp)"
PORT="$port" HOSTNAME=127.0.0.1 node .next/standalone/server.js >"$log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 60); do
  curl -fs "http://127.0.0.1:$port/api/v1/health" >/dev/null && break
  sleep 1
done
cd ../..

ENVRUNE_E2E_SERVER="http://127.0.0.1:$port" \
ENVRUNE_E2E_SUPABASE_URL="$API_URL" \
ENVRUNE_E2E_SUPABASE_SECRET_KEY="$SECRET_KEY" \
ENVRUNE_E2E_SUPABASE_PUBLISHABLE_KEY="$PUBLISHABLE_KEY" \
  go test -tags e2e -count=1 -run TestEndToEnd -v ./internal/cloud/ || { echo "--- API server log"; tail -50 "$log"; exit 1; }
