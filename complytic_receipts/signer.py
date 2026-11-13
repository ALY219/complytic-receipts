"""Signers. The agent process must never hold key material in production mode."""
import base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

ALG = "ECDSA_SHA_256"


class LocalSigner:
    """DEV ONLY. In-process key. Provides NO isolation. See THREAT_MODEL.md."""
    mode = "local-dev-in-process"

    def __init__(self, key_path=None, key_id="local-dev-1"):
        self.key_id = key_id
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._k = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._k = ec.generate_private_key(ec.SECP256R1())
            if key_path:
                with open(key_path, "wb") as f:
                    f.write(self._k.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()))

    def sign_digest(self, digest_hex: str) -> str:
        sig = self._k.sign(bytes.fromhex(digest_hex),
                           ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        return base64.b64encode(sig).decode()

    def public_pem(self) -> str:
        return self._k.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class RemoteSigner:
    """Agent-side client. Holds NO key and NO cloud credentials."""
    mode = "remote-isolated-process"

    def __init__(self, url="http://127.0.0.1:8787", key_id="isolated-dev-1"):
        self.url, self.key_id = url.rstrip("/"), key_id

    def sign_digest(self, digest_hex: str) -> str:
        import json, urllib.request
        req = urllib.request.Request(
            self.url + "/sign",
            data=json.dumps({"digest": digest_hex}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())["signature_b64"]

    def public_pem(self) -> str:
        import urllib.request
        with urllib.request.urlopen(self.url + "/pubkey", timeout=10) as r:
            return r.read().decode()


class KMSSigner:
    """Production. Non-exportable key. Only the signer role needs kms:Sign."""
    mode = "aws-kms-non-exportable"

    def __init__(self, key_id, region=None):
        import boto3  # type: ignore[import-not-found]  # optional: AWS KMS mode only
        self.key_id = key_id
        self._c = boto3.client("kms", region_name=region)

    def sign_digest(self, digest_hex: str) -> str:
        r = self._c.sign(KeyId=self.key_id,
                         Message=bytes.fromhex(digest_hex),
                         MessageType="DIGEST",
                         SigningAlgorithm="ECDSA_SHA_256")
        return base64.b64encode(r["Signature"]).decode()

    def public_pem(self) -> str:
        der = self._c.get_public_key(KeyId=self.key_id)["PublicKey"]
        body = base64.b64encode(der).decode()
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"