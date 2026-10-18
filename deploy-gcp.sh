#!/usr/bin/env bash
# Deploys LinkShield with plain gcloud commands. It needs only the Editor role:
# it never changes IAM policies, reads secrets or creates a Firestore database.
# For the locked-down setup (own service accounts, Secret Manager, Firestore) an Owner runs ./deploy.sh instead.
#
#   ./deploy-gcp.sh <project-id> [region]
#
# Trade-offs that come with Editor-only access:
#  - Both services run as the project's default compute service account.
#  - The sandbox token is a plain environment variable, visible to project editors.
#  - History, preferences and Shieldy notes are kept in BigQuery (dataset linkshield), with memory as a cache;
#    rate limits live in memory, so the API is capped at one instance.
#
# Bots: put their settings in .env.bots next to this script (it is never committed or uploaded), e.g.
#   TELEGRAM_BOT_TOKEN=123456:ABC...        TELEGRAM_BOT_USERNAME=LinkShieldBot
#   WHATSAPP_TOKEN=EAAG...                  WHATSAPP_APP_SECRET=...      WHATSAPP_PHONE_ID=...   WHATSAPP_DISPLAY_NUMBER=+1555...
# The script registers the Telegram webhook itself and prints what to paste into the Meta console for WhatsApp.
# Sign in with Google: add GOOGLE_CLIENT_ID=<web client id>.apps.googleusercontent.com to the same file
# (Google Cloud console > APIs & Services > Credentials > OAuth client ID > Web application, with the site URL
# as an authorised JavaScript origin). Without it the site works for guests only.
set -euo pipefail
PROJECT=${1:?Usage: ./deploy-gcp.sh <project-id> [region]}
REGION=${2:-asia-south1}
TAG=$(date +%Y%m%d-%H%M%S)
REPO="$REGION-docker.pkg.dev/$PROJECT/linkshield"
cd "$(dirname "$0")"

gcloud config set project "$PROJECT" >/dev/null
echo "▸ Turning on the APIs"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com compute.googleapis.com \
  aiplatform.googleapis.com webrisk.googleapis.com texttospeech.googleapis.com

echo "▸ Image repository"
gcloud artifacts repositories describe linkshield --location "$REGION" >/dev/null 2>&1 ||
  gcloud artifacts repositories create linkshield --repository-format docker --location "$REGION" --description "LinkShield images"

echo "▸ BigQuery: history, profiles and claim trends (dataset linkshield)"
gcloud services enable bigquery.googleapis.com >/dev/null
bq --project_id "$PROJECT" show "$PROJECT:linkshield" >/dev/null 2>&1 || bq --project_id "$PROJECT" --location "$REGION" mk --dataset "$PROJECT:linkshield" >/dev/null
bq --project_id "$PROJECT" --location "$REGION" query --use_legacy_sql=false --quiet >/dev/null "
CREATE TABLE IF NOT EXISTS \`$PROJECT.linkshield.history\` (uid STRING NOT NULL, scan_id STRING NOT NULL, created_at TIMESTAMP NOT NULL,
  kind STRING, level STRING, score INT64, label STRING, report STRING, source STRING, contact STRING) PARTITION BY DATE(created_at) CLUSTER BY uid;
ALTER TABLE \`$PROJECT.linkshield.history\` ADD COLUMN IF NOT EXISTS source STRING, ADD COLUMN IF NOT EXISTS contact STRING;
UPDATE \`$PROJECT.linkshield.history\` SET source = CASE WHEN STARTS_WITH(uid, 'wa-') THEN 'whatsapp' WHEN STARTS_WITH(uid, 'tg-') THEN 'telegram' ELSE 'website' END
  WHERE source IS NULL;
CREATE TABLE IF NOT EXISTS \`$PROJECT.linkshield.profiles\` (uid STRING NOT NULL, prefs STRING, chat_notes STRING, updated_at TIMESTAMP) CLUSTER BY uid;
CREATE TABLE IF NOT EXISTS \`$PROJECT.linkshield.claims_log\` (ts TIMESTAMP, claim_id STRING, claim STRING, language STRING, verdict STRING,
  confidence FLOAT64, grounded BOOL) PARTITION BY DATE(ts);"

echo "▸ Building images"
gcloud builds submit --tag "$REPO/api:$TAG" .
gcloud builds submit --config sandbox/cloudbuild.yaml --substitutions "_IMAGE=$REPO/sandbox:$TAG" .

# Generated secrets are kept across redeploys, so the services, Telegram and Meta stay in step.
current() {  # current <service> <variable>
  gcloud run services describe "$1" --region "$REGION" --format json 2>/dev/null | python3 -c 'import json,sys
try: print(next(e["value"] for e in json.load(sys.stdin)["spec"]["template"]["spec"]["containers"][0]["env"] if e["name"]==sys.argv[1]))
except Exception: pass' "$2" || true
}
fresh() { python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(40)))'; }
keep() { local v; v=$(current "$1" "$2"); [[ "$v" =~ ^[A-Za-z0-9]{40}$ ]] && echo "$v" || fresh; }
TOKEN=$(keep linkshield-sandbox SANDBOX_TOKEN)
TELEGRAM_WEBHOOK_SECRET=$(keep linkshield TELEGRAM_WEBHOOK_SECRET)
WHATSAPP_VERIFY_TOKEN=$(keep linkshield WHATSAPP_VERIFY_TOKEN)
REPORT_LINK_SECRET=$(keep linkshield REPORT_LINK_SECRET)  # signs the report links the bots send
PUBLIC_URL=$(gcloud run services describe linkshield --region "$REGION" --format 'value(status.url)' 2>/dev/null || true)
if [[ -f .env.bots ]]; then set -a; . ./.env.bots; set +a; fi

echo "▸ Sandbox worker (private: callers need an identity token from inside the project)"
gcloud run deploy linkshield-sandbox --image "$REPO/sandbox:$TAG" --region "$REGION" --port 8090 \
  --no-allow-unauthenticated --execution-environment gen2 --cpu 2 --memory 2Gi --concurrency 2 \
  --min-instances 0 --max-instances 4 --timeout 120 --set-env-vars "SANDBOX_TOKEN=$TOKEN" --quiet
SANDBOX=$(gcloud run services describe linkshield-sandbox --region "$REGION" --format 'value(status.url)')

echo "▸ API and website"
# Gemini is called through the global endpoint, which serves every current model.
ENVFILE=$(mktemp); trap 'rm -f "$ENVFILE"' EXIT
python3 - "$ENVFILE" <<PY
import json, os, sys
env = {"GOOGLE_CLOUD_PROJECT": "$PROJECT", "GOOGLE_CLOUD_LOCATION": "global", "AUTH_REQUIRED": "0", "ENABLE_FIRESTORE": "0",
       "SANDBOX_URL": "$SANDBOX", "SANDBOX_AUDIENCE": "$SANDBOX", "SANDBOX_TOKEN": "$TOKEN",
       "TELEGRAM_WEBHOOK_SECRET": "$TELEGRAM_WEBHOOK_SECRET", "WHATSAPP_VERIFY_TOKEN": "$WHATSAPP_VERIFY_TOKEN", "REPORT_LINK_SECRET": "$REPORT_LINK_SECRET", "PUBLIC_URL": "$PUBLIC_URL",
       "BQ_DATASET": "$PROJECT.linkshield", "BQ_LOCATION": "$REGION", "BQ_TABLE": "$PROJECT.linkshield.claims_log"}
for key in ("GOOGLE_CLIENT_ID", "TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_USERNAME", "WHATSAPP_TOKEN", "WHATSAPP_APP_SECRET", "WHATSAPP_PHONE_ID", "WHATSAPP_DISPLAY_NUMBER", "VIRUSTOTAL_API_KEY"):
    if os.environ.get(key):
        env[key] = os.environ[key]
with open(sys.argv[1], "w") as f:
    f.write("\n".join(f"{k}: {json.dumps(v)}" for k, v in env.items()) + "\n")
PY
gcloud run deploy linkshield --image "$REPO/api:$TAG" --region "$REGION" \
  --cpu 1 --memory 1Gi --concurrency 20 --min-instances 0 --max-instances 1 --timeout 300 --no-cpu-throttling \
  --env-vars-file "$ENVFILE" --quiet
  # --no-allow-unauthenticated
URL=$(gcloud run services describe linkshield --region "$REGION" --format 'value(status.url)')

# Opening the site to everyone is a separate, deliberate step:
#   gcloud run services update linkshield --region <region> --no-invoker-iam-check
# If an Editor is not allowed to do that, a project Owner runs:
#   gcloud run services add-iam-policy-binding linkshield --region <region> --member allUsers --role roles/run.invoker
if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
  echo "▸ Telegram webhook"
  curl -fsS "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" -d "url=$URL/api/v1/bots/telegram" \
    -d "secret_token=$TELEGRAM_WEBHOOK_SECRET" -d 'allowed_updates=["message"]' >/dev/null && echo "Telegram bot connected to $URL"
fi
if [[ -n "${WHATSAPP_TOKEN:-}" ]]; then
  echo "WhatsApp: in the Meta app dashboard (WhatsApp > Configuration) set"
  echo "  Callback URL: $URL/api/v1/bots/whatsapp"
  echo "  Verify token: $WHATSAPP_VERIFY_TOKEN"
  echo "  and subscribe to the 'messages' field."
fi
[[ -z "${GOOGLE_CLIENT_ID:-}" ]] && echo "Sign in with Google is off: add GOOGLE_CLIENT_ID to .env.bots (authorised origin: $URL)."
echo "Deployed: $URL  (sign-in page at /, the checker at /app)"
