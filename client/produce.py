"""Synthetic upstream producer: consumer health events with AES-GCM encrypted PII.

  --to bronze  insert into PII_KEY_DEMO.OPT_A.BRONZE the way the Kafka connector would (Option A)
  --to sqs     send to the ingest queue that stands in for the Kafka topic (Option B)

The producer reads the key ring from Secrets Manager: it plays the upstream system that encrypts.
"""
import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lambda"))
from hhcrypto import encrypt  # noqa: E402

FIRST = ["Ana", "Ben", "Chen", "Dana", "Eli", "Fatima", "Goran", "Hana", "Ivo", "Jun"]
LAST = ["Weber", "Okafor", "Silva", "Novak", "Kim", "Haddad", "Larsen", "Rossi"]
EVENTS = ["heart_rate", "bp_reading", "app_login", "consult_booked"]


def outputs():
    return json.loads((ROOT / "infra" / "outputs.json").read_text())["PiiKeyStaysInAws"]


def make(ring, pid):
    name = f"{random.choice(FIRST)} {random.choice(LAST)}"
    return {"patient_id": pid, "event_ts": datetime.now(timezone.utc).isoformat(),
            "event_type": random.choice(EVENTS),
            "pii": {"email": encrypt(ring, f"patient{pid}@example.org"), "full_name": encrypt(ring, name)}}


def to_bronze(records):
    import snowflake.connector
    conn = snowflake.connector.connect(connection_name=os.environ["SNOW_CONNECTION"],
                                       role="ACCOUNTADMIN", warehouse="PK_WH")
    cur = conn.cursor()
    for i in range(0, len(records), 500):
        chunk = records[i:i + 500]
        rows = ",".join(["(%s, %s)"] * len(chunk))
        args = []
        for n, r in enumerate(chunk):
            args += [json.dumps({"topic": "hh.events", "partition": 0, "offset": i + n}), json.dumps(r)]
        cur.execute("INSERT INTO PII_KEY_DEMO.OPT_A.BRONZE (RECORD_METADATA, RECORD_CONTENT) "
                    f"SELECT PARSE_JSON(column1), PARSE_JSON(column2) FROM VALUES {rows}", args)
    conn.close()


def to_sqs(records, url):
    sqs = boto3.client("sqs", region_name="eu-central-1")
    for i in range(0, len(records), 10):
        sqs.send_message_batch(QueueUrl=url, Entries=[
            {"Id": str(n), "MessageBody": json.dumps(r)} for n, r in enumerate(records[i:i + 10])])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", choices=["bronze", "sqs"], required=True)
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--start", type=int, default=None, help="first patient_id (default: time-based)")
    a = ap.parse_args()
    out = outputs()
    sm = boto3.client("secretsmanager", region_name="eu-central-1")
    ring = json.loads(sm.get_secret_value(SecretId=out["KeyRingSecretArn"])["SecretString"])
    start = a.start if a.start is not None else int(time.time()) % 10_000_000 * 100
    records = [make(ring, start + i) for i in range(a.count)]
    t0 = time.time()
    to_bronze(records) if a.to == "bronze" else to_sqs(records, out["QueueUrl"])
    print(f"sent {a.count} records to {a.to} (key {ring['current']}, ids {start}..{start + a.count - 1}) "
          f"in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
