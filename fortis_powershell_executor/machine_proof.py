"""Bound, expiring Gateway-approved machine dispatch proof, stdlib-only.

The installed owner-only listener does not enable machine dispatch by default.
The HMAC key is a dedicated owner-controlled secret distinct from the legacy
OwnerShell bearer. No AI caller or command may choose it.
"""
import hashlib
import hmac
import json
import re
import time

AUDIENCE = "fortis-powershell-executor:machine-dispatch:v1"
_FIELDS = frozenset({
    "version", "audience", "requestId", "actor", "target",
    "coreFingerprint", "commandSha256", "issuedAt", "expiresAt", "nonce",
})
_PROOF_FIELDS = frozenset({"claims", "mac"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_NONCE = re.compile(r"[a-zA-Z0-9_-]{22,128}\Z")


class MachineProofDenied(ValueError):
    pass


def canonical(data):
    try:
        return json.dumps(data, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise MachineProofDenied("MACHINE_PROOF_INVALID") from None


def validate_claims(claims, *, actor, target, request_id, command_sha256, now=None):
    if type(claims) is not dict or set(claims) != _FIELDS:
        raise MachineProofDenied("MACHINE_PROOF_INVALID")
    if (type(claims["version"]) is not int or claims["version"] != 1
            or claims["audience"] != AUDIENCE
            or type(claims["actor"]) is not str
            or _ID.fullmatch(claims["actor"]) is None
            or type(claims["target"]) is not str
            or _ID.fullmatch(claims["target"]) is None
            or type(claims["requestId"]) is not str
            or _UUID.fullmatch(claims["requestId"]) is None
            or type(claims["coreFingerprint"]) is not str
            or _HEX64.fullmatch(claims["coreFingerprint"]) is None
            or type(claims["commandSha256"]) is not str
            or _HEX64.fullmatch(claims["commandSha256"]) is None
            or type(claims["nonce"]) is not str
            or _NONCE.fullmatch(claims["nonce"]) is None
            or type(claims["issuedAt"]) is not int
            or type(claims["expiresAt"]) is not int):
        raise MachineProofDenied("MACHINE_PROOF_INVALID")
    if (claims["actor"] != actor or claims["target"] != target
            or claims["requestId"] != request_id
            or claims["commandSha256"] != command_sha256):
        raise MachineProofDenied("MACHINE_PROOF_BINDING_DENIED")
    current = int(time.time()) if now is None else now
    if (type(current) is not int or
            claims["issuedAt"] > current + 10 or
            claims["issuedAt"] < current - 120 or
            claims["expiresAt"] <= current or
            not 0 < claims["expiresAt"] - claims["issuedAt"] <= 90):
        raise MachineProofDenied("MACHINE_PROOF_EXPIRED")
    return claims


def verify(proof, key, *, actor, target, request_id, command_sha256, now=None):
    if (type(proof) is not dict or set(proof) != _PROOF_FIELDS
            or type(key) is not bytes or len(key) < 32
            or type(proof["mac"]) is not str
            or _HEX64.fullmatch(proof["mac"]) is None):
        raise MachineProofDenied("MACHINE_PROOF_INVALID")
    claims = proof["claims"]
    validate_claims(claims, actor=actor, target=target,
                    request_id=request_id, command_sha256=command_sha256, now=now)
    expected = hmac.new(key, b"fortis:machine-powershell:v1\n" + canonical(claims),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, proof["mac"]):
        raise MachineProofDenied("MACHINE_PROOF_BAD_SIGNATURE")
    return claims
