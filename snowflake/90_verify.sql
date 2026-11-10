-- Verification queries for both options (read-only).
USE WAREHOUSE PK_WH;

-- 1. Correctness: every email decrypted to the value the producer encrypted (patient<id>@example.org)
USE ROLE PK_PHI_READER;
SELECT 'A' AS opt, COUNT(*) AS total, COUNT_IF(email = 'patient' || patient_id || '@example.org') AS correct,
       COUNT_IF(email IS NULL) AS nulls, ARRAY_AGG(DISTINCT key_id) AS key_ids
FROM PII_KEY_DEMO.OPT_A.SILVER
UNION ALL
SELECT 'B', COUNT(*), COUNT_IF(email = 'patient' || patient_id || '@example.org'), COUNT_IF(email IS NULL),
       ARRAY_AGG(DISTINCT key_id)
FROM PII_KEY_DEMO.OPT_B.SILVER;

-- 2. Tag-based masking: an analyst sees masked PHI in both silver tables. Secondary roles off, otherwise
--    a user who also holds PK_PHI_READER passes IS_ROLE_IN_SESSION and sees clear text.
USE ROLE PK_ANALYST;
USE SECONDARY ROLES NONE;
SELECT 'A' AS opt, email, full_name FROM PII_KEY_DEMO.OPT_A.SILVER LIMIT 1;
SELECT 'B' AS opt, email, full_name FROM PII_KEY_DEMO.OPT_B.SILVER LIMIT 1;
USE SECONDARY ROLES ALL;

-- 3. Pipeline role: USAGE on the UDF, nothing on the secret or integration (expect errors / empty)
USE ROLE ACCOUNTADMIN;
SHOW GRANTS TO ROLE PK_PIPELINE;

-- 4. Refresh history for both silver tables
SELECT SPLIT_PART(qualified_name, '.', 2) AS opt, refresh_action, state, refresh_trigger,
       statistics:numInsertedRows::INT AS inserted, DATEDIFF('ms', refresh_start_time, refresh_end_time) AS ms,
       LEFT(state_message, 120) AS msg
FROM TABLE(PII_KEY_DEMO.INFORMATION_SCHEMA.DYNAMIC_TABLE_REFRESH_HISTORY(NAME_PREFIX => 'PII_KEY_DEMO.'))
WHERE state <> 'SCHEDULED'
ORDER BY refresh_start_time;
