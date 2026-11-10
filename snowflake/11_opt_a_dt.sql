-- Option A silver Dynamic Table, created by the pipeline role (USAGE on the UDF only).
USE ROLE PK_PIPELINE;
USE WAREHOUSE PK_WH;
CREATE OR REPLACE DYNAMIC TABLE PII_KEY_DEMO.OPT_A.SILVER
  TARGET_LAG = '1 minute' WAREHOUSE = PK_WH REFRESH_MODE = INCREMENTAL
AS
SELECT r:patient_id::INT                AS patient_id,
       r:event_ts::TIMESTAMP_TZ         AS event_ts,
       r:event_type::STRING             AS event_type,
       PII_KEY_DEMO.OPT_A.DECRYPT_PII('OPT_A.SILVER.EMAIL', e:kid, e:iv, e:ct, e:tag)     AS email,
       PII_KEY_DEMO.OPT_A.DECRYPT_PII('OPT_A.SILVER.FULL_NAME', n:kid, n:iv, n:ct, n:tag) AS full_name,
       e:kid::STRING                    AS key_id
FROM (SELECT RECORD_CONTENT AS r, RECORD_CONTENT:pii:email AS e, RECORD_CONTENT:pii:full_name AS n
      FROM PII_KEY_DEMO.OPT_A.BRONZE);

USE ROLE ACCOUNTADMIN;
ALTER DYNAMIC TABLE PII_KEY_DEMO.OPT_A.SILVER MODIFY COLUMN EMAIL SET TAG PII_KEY_DEMO.COMMON.PHI = 'email';
ALTER DYNAMIC TABLE PII_KEY_DEMO.OPT_A.SILVER MODIFY COLUMN FULL_NAME SET TAG PII_KEY_DEMO.COMMON.PHI = 'name';
