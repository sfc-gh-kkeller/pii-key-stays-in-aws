#!/usr/bin/env bash
# Remove everything setup.sh created (asks first). KMS key goes into its 7-day deletion window.
set -euo pipefail
cd "$(dirname "$0")"
CONN="${SNOW_CONNECTION:?set SNOW_CONNECTION to your snow connection name}"
read -r -p "Drop PII_KEY_DEMO, its integrations and roles, and destroy the AWS stack? [y/N] " ok
[[ "$ok" == "y" ]] || exit 0
snow sql -c "$CONN" -q "USE ROLE ACCOUNTADMIN;
  DROP DATABASE IF EXISTS PII_KEY_DEMO;
  DROP INTEGRATION IF EXISTS PK_DECRYPT_EAI; DROP INTEGRATION IF EXISTS PK_LANDING_INT;
  DROP ROLE IF EXISTS PK_PIPELINE; DROP ROLE IF EXISTS PK_PHI_READER; DROP ROLE IF EXISTS PK_ANALYST;
  DROP WAREHOUSE IF EXISTS PK_WH;" >/dev/null
(cd infra && JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 AWS_REGION=eu-central-1 \
  npx -y aws-cdk@latest destroy --force)
rm -f .secrets/caller_token.sql
