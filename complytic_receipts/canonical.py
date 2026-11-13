"""Deterministic canonicalization. The rule is part of the spec, not an implementation detail."""
import hashlib, json
from decimal import Decimal

GENESIS = "0" * 64
CANON_RULE = "JSON: sort_keys=True, separators=(',',':'), ensure_ascii=False, UTF-8, floats rejected"


class CanonicalError(ValueError):
    pass


def _reject_floats(o, path="$"):
    if isinstance(o, (float, Decimal)):
        raise CanonicalError(f"float at {path}: use strings for exact values")
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise CanonicalError(f"non-string key at {path}")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            _reject_floats(v, f"{path}[{i}]")


def canon(obj) -> bytes:
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest_of(obj) -> str:
    return sha256_hex(canon(obj))