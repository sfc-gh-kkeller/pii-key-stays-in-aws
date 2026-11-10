"""Add a new AES-256 key to the key ring in Secrets Manager and make it current (plays the CI job).

Old keys stay in the ring, so rows encrypted under them still decrypt. No person sees the value:
it is generated and written in one step. Usage: python client/rotate_key.py [--init]
"""
import argparse
import base64
import json
import os
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true", help="create the ring with k1 if it is empty")
    a = ap.parse_args()
    arn = json.loads((ROOT / "infra" / "outputs.json").read_text())["PiiKeyStaysInAws"]["KeyRingSecretArn"]
    sm = boto3.client("secretsmanager", region_name="eu-central-1")
    try:
        ring = json.loads(sm.get_secret_value(SecretId=arn)["SecretString"])
    except Exception:          # no value written yet
        ring = None
    if a.init and ring and ring.get("keys"):
        print(f"key ring exists, current {ring['current']}")
        return
    ring = ring if ring and ring.get("keys") else {"current": None, "keys": {}}
    kid = f"k{len(ring['keys']) + 1}"
    ring["keys"][kid] = base64.b64encode(os.urandom(32)).decode()
    ring["current"] = kid
    sm.put_secret_value(SecretId=arn, SecretString=json.dumps(ring))
    print(f"key ring now has {sorted(ring['keys'])}, current {kid}")


if __name__ == "__main__":
    main()
