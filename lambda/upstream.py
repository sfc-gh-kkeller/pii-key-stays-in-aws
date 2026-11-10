"""Option B: decrypt upstream. SQS (standing in for the Kafka topic) -> this Lambda -> S3 -> Snowpipe.

Each message is one record with encrypted PII fields. The Lambda decrypts them and writes one NDJSON file
per batch to S3 (SSE-KMS). Snowflake only ever receives plaintext, so the key has no reason to be there.
Failed records are reported back to SQS (partial batch response) and end up in the DLQ.
"""
import json
import os
import time
import uuid

import boto3

from hhcrypto import KeyRing, decrypt

PII_FIELDS = ("email", "full_name")
BUCKET = os.environ.get("LANDING_BUCKET", "")
PREFIX = os.environ.get("LANDING_PREFIX", "silver-in/")
_keys = KeyRing(os.environ.get("KEYRING_SECRET_ARN", ""), ttl=int(os.environ.get("KEY_TTL_S", "300")))
_s3 = None


def transform(ring: dict, record: dict) -> dict:
    out = {k: v for k, v in record.items() if k != "pii"}
    for f in PII_FIELDS:
        enc = record["pii"].get(f)
        out[f] = None if enc is None else decrypt(ring, enc)
        out[f + "_kid"] = None if enc is None else enc["kid"]
    return out


def handler(event, context):
    global _s3
    t0 = time.time()
    rows, failures, parsed = [], [], []
    for msg in event.get("Records", []):
        try:
            parsed.append((msg["messageId"], json.loads(msg["body"])))
        except ValueError:
            failures.append({"itemIdentifier": msg["messageId"]})
    kids = {f["kid"] for _, r in parsed for f in (r.get("pii") or {}).values() if isinstance(f, dict) and "kid" in f}
    ring = _keys.get(need_kids=kids)
    for mid, rec in parsed:
        try:
            row = transform(ring, rec)
            row["src_message_id"] = mid
            rows.append(row)
        except Exception:
            failures.append({"itemIdentifier": mid})
    key = None
    if rows:
        _s3 = _s3 or boto3.client("s3")
        key = f"{PREFIX}{time.strftime('%Y/%m/%d/%H')}/{uuid.uuid4().hex}.json"
        _s3.put_object(Bucket=BUCKET, Key=key, ContentType="application/x-ndjson",
                       Body="\n".join(json.dumps(r) for r in rows).encode())
    print(json.dumps({"audit": "upstream_decrypt", "request_id": getattr(context, "aws_request_id", None),
                      "rows": len(rows), "failed": len(failures), "s3_key": key,
                      "ms": round((time.time() - t0) * 1000)}))
    return {"batchItemFailures": failures}
