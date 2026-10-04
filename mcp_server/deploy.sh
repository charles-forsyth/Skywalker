#!/usr/bin/env bash
# Deploy the Skywalker MCP server to Cloud Run (same service name and URLs).
#
# Infrastructure (each step is idempotent and says "ok" when already in place):
#   - service account  skywalker-mcp@$PROJECT  (no Google Cloud data roles at all:
#                      every tool reads as the signed-in caller)
#   - bucket           gs://$PROJECT-skywalker-mcp-data  (sealed OAuth state and
#                      each person's sealed Google refresh token)
#   - secrets          skywalker-mcp-google-oauth-client-id / -secret (existing)
#                      skywalker-mcp-seal-key  (32 random bytes, created once)
#                      skywalker-mcp-users     (users.yaml; uploaded when changed)
#
# users.yaml lives outside the repo: $USERS (default ~/.config/skywalker/mcp-users.yaml).
# The billing export table, billing account and fleet folders come from the env
# below (not secrets, but not in the repo's code either).
set -euo pipefail

cd "$(dirname "$0")"

SERVICE="skywalker-mcp-server"
REGION="us-central1"
PROJECT="${PROJECT:-ucr-research-computing}"
SA="${SA:-skywalker-mcp@${PROJECT}.iam.gserviceaccount.com}"
BUCKET="${PROJECT}-skywalker-mcp-data"
USERS="${USERS:-$HOME/.config/skywalker/mcp-users.yaml}"
SETTINGS="${SETTINGS:-$HOME/.config/skywalker/mcp-server.env}"

have() { "$@" >/dev/null 2>&1; }

# Refuse to ship uncommitted code: the image must match a commit.
if [[ -n "$(git -C .. status --porcelain -- src/skywalker mcp_server)" ]]; then
  echo "Uncommitted changes in src/skywalker or mcp_server; commit first." >&2; exit 1
fi
[[ -f "$USERS" ]] || { echo "No users file at $USERS (see users.example.yaml)." >&2; exit 1; }
[[ -f "$SETTINGS" ]] || { echo "No settings at $SETTINGS (SKYWALKER_BILLING_TABLE=..., see README)." >&2; exit 1; }
uv run --no-project --with pyyaml python -c "import sys; sys.path.insert(0, '.'); from users import parse; c = parse(open('$USERS').read()); print(f'ok   users.yaml: {len(c.users)} users, {len(c.clients)} program clients')"
# shellcheck disable=SC1090
source "$SETTINGS"
: "${SKYWALKER_BILLING_TABLE:?}" "${SKYWALKER_BILLING_ACCOUNT:?}" "${SKYWALKER_JOB_PROJECT:?}"
SKYWALKER_FLEET_SCOPES="${SKYWALKER_FLEET_SCOPES:-}"
SKYWALKER_QUOTA_PROJECT="${SKYWALKER_QUOTA_PROJECT:-$PROJECT}"

# --- runtime service account (no data roles) --------------------------------------
if have gcloud iam service-accounts describe "$SA" --project "$PROJECT"; then echo "ok   $SA"
else
  gcloud iam service-accounts create "${SA%%@*}" --project "$PROJECT" \
    --display-name "Skywalker MCP server (no data roles; reads as the caller)"
fi

# --- bucket for sealed state --------------------------------------------------------
if have gcloud storage buckets describe "gs://$BUCKET"; then echo "ok   gs://$BUCKET"
else
  gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location "$REGION" \
    --uniform-bucket-level-access --public-access-prevention --soft-delete-duration=0
fi
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member "serviceAccount:$SA" --role roles/storage.objectUser >/dev/null
echo "ok   $SA can use gs://$BUCKET"

# --- secrets ----------------------------------------------------------------------
if have gcloud secrets describe skywalker-mcp-seal-key --project "$PROJECT"; then echo "ok   skywalker-mcp-seal-key"
else
  python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='), end='')" |
    gcloud secrets create skywalker-mcp-seal-key --project "$PROJECT" --replication-policy automatic --data-file=-
fi
have gcloud secrets describe skywalker-mcp-users --project "$PROJECT" ||
  gcloud secrets create skywalker-mcp-users --project "$PROJECT" --replication-policy automatic
current="$(gcloud secrets versions access latest --secret skywalker-mcp-users --project "$PROJECT" 2>/dev/null || true)"
if [[ "$current" == "$(cat "$USERS")" ]]; then echo "ok   skywalker-mcp-users is current"
else
  gcloud secrets versions add skywalker-mcp-users --project "$PROJECT" --data-file="$USERS"
  echo "uploaded $USERS as a new version of skywalker-mcp-users"
fi
for s in skywalker-mcp-google-oauth-client-id skywalker-mcp-google-oauth-client-secret \
         skywalker-mcp-seal-key skywalker-mcp-users; do
  gcloud secrets add-iam-policy-binding "$s" --project "$PROJECT" \
    --member "serviceAccount:$SA" --role roles/secretmanager.secretAccessor >/dev/null
done
echo "ok   $SA can read its four secrets"

# --- build and deploy -------------------------------------------------------------
REV="$(git -C .. rev-parse --short HEAD)"
rm -rf skywalker_src
mkdir -p skywalker_src
cp ../src/skywalker/__init__.py skywalker_src/
cp -r ../src/skywalker/intel skywalker_src/intel
find skywalker_src -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
trap 'rm -rf skywalker_src' EXIT

echo "Deploying ${SERVICE} (skywalker ${REV}, as ${SA})..."
# min 1 / max 1: always warm (Chuck), and one instance keeps single-use codes and
# rotating refresh tokens single use. No session affinity: /mcp is stateless.
gcloud run deploy "${SERVICE}" \
  --source . \
  --project "${PROJECT}" \
  --region "${REGION}" \
  --service-account "${SA}" \
  --set-env-vars "^@^SKYWALKER_REV=${REV}@SKYWALKER_MCP_USERS=/users/users.yaml@SKYWALKER_MCP_DATA=/data@SKYWALKER_BILLING_TABLE=${SKYWALKER_BILLING_TABLE}@SKYWALKER_BILLING_ACCOUNT=${SKYWALKER_BILLING_ACCOUNT}@SKYWALKER_JOB_PROJECT=${SKYWALKER_JOB_PROJECT}@SKYWALKER_FLEET_SCOPES=${SKYWALKER_FLEET_SCOPES}@SKYWALKER_QUOTA_PROJECT=${SKYWALKER_QUOTA_PROJECT}@SKYWALKER_DOMAIN=${SKYWALKER_DOMAIN:-ucr.edu}" \
  --set-secrets "GOOGLE_OAUTH_CLIENT_ID=skywalker-mcp-google-oauth-client-id:latest,GOOGLE_OAUTH_CLIENT_SECRET=skywalker-mcp-google-oauth-client-secret:latest,MCP_SEAL_KEY=skywalker-mcp-seal-key:latest,/users/users.yaml=skywalker-mcp-users:latest" \
  --remove-env-vars MCP_JWT_SECRET \
  --add-volume "name=data,type=cloud-storage,bucket=${BUCKET}" \
  --add-volume-mount "volume=data,mount-path=/data" \
  --execution-environment gen2 \
  --memory 1Gi \
  --cpu 1 \
  --min-instances 1 \
  --max-instances 1 \
  --no-session-affinity \
  --timeout 3600s

# The OAuth endpoints must be reachable by browsers and MCP clients; the server's
# own sign-in is the gate (every MCP route answers 401 without a token).
gcloud run services add-iam-policy-binding "${SERVICE}" --project "${PROJECT}" --region "${REGION}" \
  --member allUsers --role roles/run.invoker >/dev/null
echo "ok   ${SERVICE} reachable (sign-in enforced by the server)"
gcloud run services describe "${SERVICE}" --project "${PROJECT}" --region "${REGION}" --format "value(status.url)"
