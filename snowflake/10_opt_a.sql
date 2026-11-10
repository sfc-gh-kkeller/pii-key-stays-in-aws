-- Option A: the Dynamic Table calls a VOLATILE, vectorized External Access UDF that sends batches of
-- ciphertext to the decrypt Lambda in AWS and gets plaintext back. The AES key never enters Snowflake.
-- Variables: &{decrypt_url} &{decrypt_host}
-- The secret DECRYPT_CALLER_TOKEN is created by setup.sh from Secrets Manager (value never in git).
USE ROLE ACCOUNTADMIN;
USE WAREHOUSE PK_WH;
USE SCHEMA PII_KEY_DEMO.OPT_A;

-- Bronze as the Snowflake Kafka connector lands it: PII fields still AES-GCM encrypted
CREATE TABLE IF NOT EXISTS BRONZE (RECORD_METADATA VARIANT, RECORD_CONTENT VARIANT) CHANGE_TRACKING = TRUE;
GRANT SELECT ON TABLE BRONZE TO ROLE PK_PIPELINE;

CREATE OR REPLACE NETWORK RULE DECRYPT_EGRESS MODE = EGRESS TYPE = HOST_PORT VALUE_LIST = ('&{decrypt_host}:443');
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION PK_DECRYPT_EAI
  ALLOWED_NETWORK_RULES = (PII_KEY_DEMO.OPT_A.DECRYPT_EGRESS)
  ALLOWED_AUTHENTICATION_SECRETS = (PII_KEY_DEMO.OPT_A.DECRYPT_CALLER_TOKEN)
  ENABLED = TRUE;

-- Owned by ACCOUNTADMIN (stand-in for a security-owned role); runs with owner's rights.
-- VOLATILE: replacing it does not reinitialize the DT (an IMMUTABLE UDF did, in the 2b test).
-- caller is a constant per column, sent to the Lambda for its audit line.
CREATE OR REPLACE SECURE FUNCTION DECRYPT_PII(caller STRING, kid STRING, iv STRING, ct STRING, tag STRING)
RETURNS STRING
LANGUAGE PYTHON
VOLATILE
RUNTIME_VERSION = '3.12'
HANDLER = 'decrypt_batch'
EXTERNAL_ACCESS_INTEGRATIONS = (PK_DECRYPT_EAI)
SECRETS = ('token' = PII_KEY_DEMO.OPT_A.DECRYPT_CALLER_TOKEN)
PACKAGES = ('pandas', 'requests')
AS $$
import pandas, requests, _snowflake
from _snowflake import vectorized

URL = '&{decrypt_url}'
_http = requests.Session()

@vectorized(input=pandas.DataFrame, max_batch_size=2000)
def decrypt_batch(df):
    items = [None if kid is None else {"kid": kid, "iv": iv, "ct": ct, "tag": tag}
             for _, kid, iv, ct, tag in df.itertuples(index=False)]
    r = _http.post(URL, timeout=30,
                   json={"caller": str(df.iloc[0, 0]), "items": items},
                   headers={"Authorization": "Bearer " + _snowflake.get_generic_secret_string('token')})
    r.raise_for_status()
    plain = r.json()["plain"]
    # Fail closed: a row that should decrypt but did not fails the refresh (and is retried) instead of
    # being committed as NULL, which an incremental DT would never revisit.
    bad = sum(1 for it, p in zip(items, plain) if it is not None and p is None)
    if bad:
        raise ValueError(f"decrypt service could not decrypt {bad} of {len(items)} values")
    return pandas.Series(plain)
$$;
GRANT USAGE ON FUNCTION DECRYPT_PII(STRING, STRING, STRING, STRING, STRING) TO ROLE PK_PIPELINE;
