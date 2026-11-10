"""AES-256-GCM field encryption shared by the producer and both Lambdas.

An encrypted field is {"kid": key id, "iv": b64, "ct": b64, "tag": b64}. The key ring lives in
Secrets Manager as {"current": "k1", "keys": {"k1": "<b64 32 bytes>", ...}} so rotation adds a
key without breaking rows encrypted under older ones.
"""
import base64
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_b64e = lambda b: base64.b64encode(b).decode()
_b64d = base64.b64decode


def encrypt(keyring: dict, plaintext: str) -> dict:
    kid = keyring["current"]
    iv = os.urandom(12)
    out = AESGCM(_b64d(keyring["keys"][kid])).encrypt(iv, plaintext.encode(), None)
    return {"kid": kid, "iv": _b64e(iv), "ct": _b64e(out[:-16]), "tag": _b64e(out[-16:])}


def decrypt(keyring: dict, field: dict) -> str:
    key = _b64d(keyring["keys"][field["kid"]])
    return AESGCM(key).decrypt(_b64d(field["iv"]), _b64d(field["ct"]) + _b64d(field["tag"]), None).decode()


class KeyRing:
    """Reads the key ring from Secrets Manager and keeps it in Lambda memory for `ttl` seconds.

    Every refresh is a GetSecretValue call by the Lambda role, which CloudTrail records.
    """

    def __init__(self, secret_arn: str, ttl: int = 300, client=None):
        self.secret_arn, self.ttl, self._client = secret_arn, ttl, client
        self._ring, self._at = None, 0.0

    def get(self, need_kids=()) -> dict:
        """Cached ring; reloaded after `ttl`, or at once if it lacks a key id in `need_kids` (a rotation)."""
        stale = self._ring is None or time.time() - self._at > self.ttl
        if not stale and any(k not in self._ring.get("keys", {}) for k in need_kids):
            stale = True
        if stale:
            if self._client is None:
                import boto3
                self._client = boto3.client("secretsmanager")
            self._ring = json.loads(self._client.get_secret_value(SecretId=self.secret_arn)["SecretString"])
            self._at = time.time()
        return self._ring
