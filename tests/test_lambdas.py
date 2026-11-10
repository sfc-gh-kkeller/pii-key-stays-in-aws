import base64
import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
import hhcrypto  # noqa: E402

RING = {"current": "k2", "keys": {"k1": base64.b64encode(b"1" * 32).decode(),
                                  "k2": base64.b64encode(b"2" * 32).decode()}}


class FakeSM:
    def __init__(self, value):
        self.value, self.calls = value, 0

    def get_secret_value(self, SecretId):
        self.calls += 1
        return {"SecretString": json.dumps(self.value)}


def test_roundtrip_and_old_key_still_decrypts():
    f = hhcrypto.encrypt(RING, "a@b.org")
    assert f["kid"] == "k2" and hhcrypto.decrypt(RING, f) == "a@b.org"
    old = hhcrypto.encrypt({**RING, "current": "k1"}, "x")
    assert hhcrypto.decrypt(RING, old) == "x"


def test_tamper_fails():
    f = hhcrypto.encrypt(RING, "secret")
    f["tag"] = base64.b64encode(b"\0" * 16).decode()
    with pytest.raises(Exception):
        hhcrypto.decrypt(RING, f)


def test_keyring_caches():
    sm = FakeSM(RING)
    kr = hhcrypto.KeyRing("arn", ttl=300, client=sm)
    kr.get(); kr.get()
    assert sm.calls == 1


def test_keyring_reloads_on_unknown_kid():
    sm = FakeSM({"current": "k1", "keys": {"k1": RING["keys"]["k1"]}})
    kr = hhcrypto.KeyRing("arn", ttl=300, client=sm)
    kr.get()
    sm.value = RING                      # rotation added k2
    assert "k2" in kr.get(need_kids={"k2"})["keys"] and sm.calls == 2
    kr.get(need_kids={"k1"})
    assert sm.calls == 2


@pytest.fixture
def decrypt_api(monkeypatch):
    import decrypt_api as m
    monkeypatch.setattr(m, "_keys", hhcrypto.KeyRing("k", client=FakeSM(RING)))
    monkeypatch.setattr(m, "_token", hhcrypto.KeyRing("t", client=FakeSM({"token": "tok"})))
    return m


def _event(items, token="tok"):
    return {"headers": {"authorization": f"Bearer {token}"}, "requestContext": {"http": {"sourceIp": "1.2.3.4"}},
            "body": json.dumps({"caller": "T", "items": items})}


def test_decrypt_api_ok_and_null_on_bad_item(decrypt_api, capsys):
    good = hhcrypto.encrypt(RING, "p@x.org")
    bad = {**good, "tag": base64.b64encode(b"\0" * 16).decode()}
    r = decrypt_api.handler(_event([good, None, bad]), types.SimpleNamespace(aws_request_id="r1"))
    assert r["statusCode"] == 200
    assert json.loads(r["body"])["plain"] == ["p@x.org", None, None]
    log = capsys.readouterr().out
    assert "p@x.org" not in log and good["ct"] not in log and '"failed": 1' in log


def test_decrypt_api_rejects_wrong_token(decrypt_api):
    r = decrypt_api.handler(_event([], token="nope"), types.SimpleNamespace(aws_request_id="r2"))
    assert r["statusCode"] == 401


def test_upstream_writes_plaintext_and_reports_failures(monkeypatch):
    import upstream as m
    monkeypatch.setattr(m, "_keys", hhcrypto.KeyRing("k", client=FakeSM(RING)))
    puts = []
    monkeypatch.setattr(m, "_s3", types.SimpleNamespace(put_object=lambda **kw: puts.append(kw)))
    rec = {"patient_id": 7, "event_ts": "2026-11-10T00:00:00Z",
           "pii": {"email": hhcrypto.encrypt(RING, "e@x.org"), "full_name": hhcrypto.encrypt(RING, "Ann")}}
    ev = {"Records": [{"messageId": "m1", "body": json.dumps(rec)}, {"messageId": "m2", "body": "not json"}]}
    out = m.handler(ev, types.SimpleNamespace(aws_request_id="r3"))
    assert out == {"batchItemFailures": [{"itemIdentifier": "m2"}]}
    row = json.loads(puts[0]["Body"].decode())
    assert row["email"] == "e@x.org" and row["full_name"] == "Ann" and row["email_kid"] == "k2"
    assert "pii" not in row
