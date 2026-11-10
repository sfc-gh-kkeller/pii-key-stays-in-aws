# Test results (2026-11-10)

Snowflake account on AWS eu-central-1 (X-Small warehouse `PK_WH`), AWS stack `PiiKeyStaysInAws` in
eu-central-1. Both silver DTs: `TARGET_LAG = '1 minute'`, `REFRESH_MODE = INCREMENTAL`, owned by `PK_PIPELINE`.
Synthetic records: patient id, event, AES-256-GCM encrypted `email` and `full_name`.

## Summary

| Check | Option A (DT calls AWS decrypt) | Option B (decrypt upstream) |
| --- | --- | --- |
| DT created INCREMENTAL, `refresh_mode_reason` NULL | yes | yes |
| Scheduled refreshes (user `SYSTEM`) process new rows only | yes | yes |
| 10,000 rows: refresh time | 11.4 s (2 columns, about 57 calls each) | 0.7 s + 0.8 s (two loads) |
| 2,000 rows: refresh time | 9.4 – 9.8 s | 0.8 s |
| Correct values after 3 keys (k1, k2, k3) | 14,500 / 14,500 | 14,500 / 14,500 |
| AES key in Snowflake | never | never |
| Decrypt function or integration in Snowflake | yes (EAI, secure UDF, caller-token secret) | no |
| PHI in Snowflake | silver only (bronze is ciphertext) | bronze and silver (bronze tagged and masked) |
| Tag masking for `PK_ANALYST` (secondary roles off) | `***PHI***` | `***PHI***` |
| `PK_PIPELINE` privileges | USAGE on `DECRYPT_PII` only; nothing on secret/EAI | SELECT on bronze only |
| Caller token in query history | not found | n/a |
| AWS audit | one log line per call: column, rows, key ids, source IP | one log line per batch: rows, failures, S3 file |
| CloudTrail `GetSecretValue` on the key ring | Lambda roles only (+ admin running producer/rotation) | same |
| Dead-letter queue after all tests | n/a | 0 |

## Key rotation: the finding that matters

First rotation (k1 to k2) with the Lambdas' 5-minute key cache:

* **Option A wrote 2,000 rows with `NULL` email and name.** The Lambda did not know k2 yet and returned null; the UDF
  accepted it and the DT committed the rows. An incremental DT never revisits committed rows, so they stayed wrong
  until the DT was recreated (11 s full re-decrypt of 12,000 rows).
* **Option B recovered by itself.** 1,286 records failed decrypt, went back to SQS (partial batch response) and loaded
  on retry: 2,000 / 2,000 correct, no duplicates, DLQ empty.

Fix, now in the code:

* The key ring reloads at once when a batch names a key id it does not have (`KeyRing.get(need_kids=...)`).
* Option A's UDF fails closed: if any non-null input comes back null, it raises, so the refresh fails and retries
  instead of committing bad rows.

Second rotation (k2 to k3) with warm caches after the fix: both options 2,000 / 2,000 correct on the first refresh.

## What each option does and does not prove

Option A

* The AES key stays in AWS: Snowflake sends ciphertext and gets plaintext back.
* Snowflake still holds a credential (the caller token, a GENERIC_STRING secret) that lets the UDF request decryption.
  It is not the key, but whoever can run the UDF can decrypt, which is the same power the pipeline has today.
* PHI ciphertext leaves Snowflake and plaintext comes back over TLS (public Lambda URL in the demo; AWS PrivateLink
  for outbound traffic and an IAM-authorised URL would be the production shape).
* AWS logs show the column and time, not the Snowflake query id; correlate with `DYNAMIC_TABLE_REFRESH_HISTORY`.
* Refresh time grows with rows (about 5 ms/row for two columns at this scale). Lambda concurrency and
  `max_batch_size` are the levers.
* If AWS is unavailable, refreshes fail and catch up later (no silent nulls, after the fix).

Option B

* Nothing in Snowflake can decrypt: no key, no decrypt function, no integration to AWS other than the storage read.
* The requirement "the key cannot leave AWS" holds by construction; "who used the key" is answered entirely in AWS.
* Snowflake holds plaintext PHI from bronze onward, so bronze needs the same tag masking, grants and alerts as silver.
* The pipeline changes: Kafka consumer (Lambda, or MSK + Lambda) and S3 + Snowpipe instead of the Kafka connector
  writing straight to Snowflake.

## Not tested

* Real Kafka / MSK (SQS stands in), Snowpipe Streaming, AWS PrivateLink for outbound traffic.
* ACCESS_HISTORY entries (Account Usage latency).
* Load beyond 14,500 rows and Lambda throttling behaviour.
