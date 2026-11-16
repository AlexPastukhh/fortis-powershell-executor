import hashlib
import hmac
import unittest

from fortis_powershell_executor.machine_proof import (
    AUDIENCE, MachineProofDenied, canonical, verify,
)

KEY = b"unit-only-key-32-bytes-not-for-production--"
CLAIMS = {
    "version": 1, "audience": AUDIENCE,
    "actor": "fortis-repo", "target": "windows-owner",
    "requestId": "01234567-89ab-4def-8abc-0123456789ab",
    "coreFingerprint": "a" * 64, "commandSha256": hashlib.sha256(b"Get-Date").hexdigest(),
    "issuedAt": 1000, "expiresAt": 1060, "nonce": "Cq7d9GsbJ1E7TLQwDfcvD7qL",
}


def sign(claims):
    return {"claims": claims, "mac": hmac.new(
        KEY, b"fortis:machine-powershell:v1\n" + canonical(claims),
        hashlib.sha256).hexdigest()}


class MachineProofTests(unittest.TestCase):
    def check(self, proof, **overrides):
        return verify(proof, KEY, actor=overrides.get("actor", CLAIMS["actor"]),
                      target=overrides.get("target", CLAIMS["target"]),
                      request_id=overrides.get("request_id", CLAIMS["requestId"]),
                      command_sha256=overrides.get("command_sha256", CLAIMS["commandSha256"]),
                      now=overrides.get("now", 1030))

    def test_exact_valid_proof(self):
        self.assertEqual(self.check(sign(CLAIMS)), CLAIMS)

    def test_command_uuid_actor_target_are_bound(self):
        p = sign(CLAIMS)
        for kw in [
            {"actor": "someone-else"}, {"target": "other-windows"},
            {"request_id": "01234567-89ab-4def-8abc-0123456789ac"},
            {"command_sha256": "0" * 64},
        ]:
            with self.subTest(kw=kw), self.assertRaises(MachineProofDenied):
                self.check(p, **kw)

    def test_changed_approved_fingerprint_or_nonce_breaks_mac(self):
        for key, value in [("coreFingerprint", "f"*64),
                           ("nonce", "AbcdefGHIJKLMNOPQrsTUVWX")]:
            with self.subTest(key=key), self.assertRaises(MachineProofDenied):
                self.check({**sign(CLAIMS), "claims": {**CLAIMS, key: value}})

    def test_expiry_future_time_and_too_long_ttl(self):
        p=sign(CLAIMS)
        for now in (1060, 989, 9999):
            with self.subTest(now=now), self.assertRaises(MachineProofDenied):
                self.check(p, now=now)
        with self.assertRaises(MachineProofDenied):
            self.check(sign({**CLAIMS, "expiresAt": 1200}))

    def test_wrong_audience_extra_claims_weak_key_and_bad_mac(self):
        for claims in [
            {**CLAIMS, "audience": "other"},
            {**CLAIMS, "approved": True},
            {**CLAIMS, "version": "1"},
        ]:
            with self.subTest(claims=claims), self.assertRaises(MachineProofDenied):
                self.check(sign(claims))
        with self.assertRaises(MachineProofDenied):
            verify(sign(CLAIMS), b"short", actor=CLAIMS["actor"], target=CLAIMS["target"],
                   request_id=CLAIMS["requestId"], command_sha256=CLAIMS["commandSha256"], now=1030)
        with self.assertRaises(MachineProofDenied):
            self.check({**sign(CLAIMS), "mac": "0"*64})

    def test_no_secret_or_command_in_errors(self):
        with self.assertRaises(MachineProofDenied) as ctx:
            self.check({"claims":CLAIMS,"mac":"xyz"})
        self.assertNotIn("unit-only",str(ctx.exception))
        self.assertNotIn("Get-Date",str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
