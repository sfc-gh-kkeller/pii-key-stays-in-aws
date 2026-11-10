"""Option A: decrypt-as-a-service. A Snowflake UDF sends a batch of encrypted fields, gets plaintext back.

The AES key ring never leaves this function. The caller proves itself with a bearer token that only
allows decrypt calls (it is not the key). Every call writes one audit line: caller, row count, key ids,
source IP, request id. Plaintext and ciphertext are never logged.

Request:  {"caller": "PII_KEY_DEMO.OPT_A.SILVER", "items": [{"kid","iv","ct","tag"}, ...]}
Response: {"plain": ["...", null, ...]}   (null for an item that fails to decrypt)
"""
import hmac
import json
import os
import time

from hhcrypto import KeyRing, decrypt

MAX_ITEMS = int(os.environ.get("MAX_ITEMS", "5000"))
_keys = KeyRing(os.environ.get("KEYRING_SECRET_ARN", ""), ttl=int(os.environ.get("KEY_TTL_S", "300")))
_token = KeyRing(os.environ.get("CALLER_TOKEN_SECRET_ARN", ""), ttl=300)


def _resp(code, body):
    return {"statusCode": code, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}


def handler(event, context):
    t0 = time.time()
    rc = event.get("requestContext", {})
    audit = {"audit": "decrypt", "request_id": getattr(context, "aws_request_id", None),
             "source_ip": rc.get("http", {}).get("sourceIp")}
    auth = (event.get("headers") or {}).get("authorization", "")
    expected = "Bearer " + _token.get()["token"]
    if not hmac.compare_digest(auth.encode(), expected.encode()):
        print(json.dumps({**audit, "result": "denied"}))
        return _resp(401, {"error": "unauthorized"})
    try:
        body = json.loads(event.get("body") or "{}")
        items = body["items"]
    except (ValueError, KeyError):
        return _resp(400, {"error": "bad request"})
    if len(items) > MAX_ITEMS:
        return _resp(413, {"error": f"max {MAX_ITEMS} items"})

    ring = _keys.get(need_kids={it["kid"] for it in items if it})
    plain, failed = [], 0
    for it in items:
        try:
            plain.append(None if it is None else decrypt(ring, it))
        except Exception:
            plain.append(None)
            failed += 1
    print(json.dumps({**audit, "result": "ok", "caller": str(body.get("caller", ""))[:200],
                      "rows": len(items), "failed": failed,
                      "kids": sorted({it["kid"] for it in items if it}),
                      "ms": round((time.time() - t0) * 1000)}))
    return _resp(200, {"plain": plain})
