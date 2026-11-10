#!/usr/bin/env bash
# End-to-end setup for both options (needs: aws login, a snow connection, Docker for Lambda bundling).
#   SNOW_CONNECTION=<name> bash setup.sh
set -euo pipefail
cd "$(dirname "$0")"
CONN="${SNOW_CONNECTION:?set SNOW_CONNECTION to your snow connection name}"
CDK="npx -y aws-cdk@latest"
export AWS_REGION=eu-central-1 CDK_DEFAULT_REGION=eu-central-1 JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
mkdir -p .secrets && chmod 700 .secrets
sfq() { snow sql -c "$CONN" --format json -q "$1"; }
out() { python3 -c "import json;print(json.load(open('infra/outputs.json'))['PiiKeyStaysInAws']['$1'])"; }

echo "== 1. Snowflake common objects (database, roles, PHI tag masking)"
DEMO_USER=$(sfq "SELECT CURRENT_USER() AS U" | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['U'])")
snow sql -c "$CONN" -f snowflake/00_common.sql -D "demo_user=$DEMO_USER" >/dev/null

echo "== 2. AWS stack (pass 1)"
(cd infra && $CDK deploy --require-approval never --outputs-file outputs.json ${CDK_EXTRA:-})

echo "== 3. AES key ring in Secrets Manager (a CI job)"
pixi run python client/rotate_key.py --init

echo "== 4. Option A: caller token -> Snowflake SECRET, EAI, decrypt UDF, silver DT"
DECRYPT_URL=$(out DecryptUrl); DECRYPT_HOST=$(python3 -c "import sys,urllib.parse;print(urllib.parse.urlparse(sys.argv[1]).hostname)" "$DECRYPT_URL")
aws secretsmanager get-secret-value --secret-id "$(out CallerTokenSecretArn)" --query SecretString --output text \
  | python3 -c "import json,sys;t=json.load(sys.stdin)['token'];print(f\"USE ROLE ACCOUNTADMIN; CREATE OR REPLACE SECRET PII_KEY_DEMO.OPT_A.DECRYPT_CALLER_TOKEN TYPE = GENERIC_STRING SECRET_STRING = '{t}';\")" \
  > .secrets/caller_token.sql
chmod 600 .secrets/caller_token.sql
snow sql -c "$CONN" -f .secrets/caller_token.sql >/dev/null
snow sql -c "$CONN" -f snowflake/10_opt_a.sql -D "decrypt_url=$DECRYPT_URL" -D "decrypt_host=$DECRYPT_HOST" >/dev/null
snow sql -c "$CONN" -f snowflake/11_opt_a_dt.sql >/dev/null

echo "== 5. Option B: storage integration"
BUCKET=$(out BucketName); ROLE_ARN=$(out SnowflakeRoleArn)
snow sql -c "$CONN" -f snowflake/20_opt_b_integration.sql -D "role_arn=$ROLE_ARN" -D "bucket=$BUCKET" >/dev/null
read -r SF_USER SF_EXT < <(sfq "DESC STORAGE INTEGRATION PK_LANDING_INT" | python3 -c "
import json,sys;d={r['property']:r['property_value'] for r in json.load(sys.stdin)}
print(d['STORAGE_AWS_IAM_USER_ARN'], d['STORAGE_AWS_EXTERNAL_ID'])")

echo "== 6. AWS stack (pass 2: trust Snowflake's storage IAM user + external id)"
(cd infra && $CDK deploy --require-approval never --outputs-file outputs.json \
  -c sf_storage_iam_user_arn="$SF_USER" -c sf_storage_external_id="$SF_EXT" ${CDK_EXTRA:-})

echo "== 7. Option B: stage, bronze, pipe; S3 event notifications -> Snowpipe queue; silver DT"
sleep 10   # IAM trust propagation
snow sql -c "$CONN" -f snowflake/21_opt_b_landing.sql -D "bucket=$BUCKET" >/dev/null
CHANNEL=$(sfq "SHOW PIPES LIKE 'LANDING_PIPE' IN SCHEMA PII_KEY_DEMO.OPT_B" | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['notification_channel'])")
aws s3api put-bucket-notification-configuration --bucket "$BUCKET" --notification-configuration \
  "{\"QueueConfigurations\":[{\"QueueArn\":\"$CHANNEL\",\"Events\":[\"s3:ObjectCreated:*\"],\"Filter\":{\"Key\":{\"FilterRules\":[{\"Name\":\"prefix\",\"Value\":\"silver-in/\"}]}}}]}"
snow sql -c "$CONN" -f snowflake/22_opt_b_dt.sql >/dev/null

echo; echo "Done. Try: pixi run produce-a 1000   and   pixi run produce-b 1000"
