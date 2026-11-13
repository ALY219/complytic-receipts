"""Isolated signing process. The agent talks to this over HTTP and never receives key material."""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from complytic_receipts.signer import LocalSigner, KMSSigner


def build():
    if len(sys.argv) > 1 and sys.argv[1].startswith("arn:"):
        arn = sys.argv[1]
        if any(p in arn for p in ("REGION", "ACCOUNT", "KEY-ID")):
            raise SystemExit("That is the placeholder ARN. Substitute your real KMS key ARN.")
        parts = arn.split(":")
        if len(parts) < 6 or not parts[3]:
            raise SystemExit("Malformed ARN. Expected arn:aws:kms:REGION:ACCOUNT:key/UUID")
        return KMSSigner(arn, region=parts[3])
    return LocalSigner(key_path="signer_key.pem", key_id="isolated-dev-1")


SIGNER = build()


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/pubkey":
            self._send(200, SIGNER.public_pem().encode(), "application/x-pem-file")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/sign":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0))
        try:
            d = json.loads(self.rfile.read(n))
            digest = d["digest"]
            if len(digest) != 64:
                raise ValueError("digest must be 64 hex chars")
            bytes.fromhex(digest)
            self._send(200, {"signature_b64": SIGNER.sign_digest(digest),
                             "key_id": SIGNER.key_id})
        except Exception as e:
            self._send(400, {"error": str(e)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    import getpass
    print("signer listening on 127.0.0.1:8787", flush=True)
    print(f"key backend : {SIGNER.mode}", flush=True)
    print(f"topology    : separate process, OS user '{getpass.getuser()}'", flush=True)
    if SIGNER.mode != "aws-kms-non-exportable":
        print("WARNING: key is on local disk. An agent running as this same OS user", flush=True)
        print("         can read it. This is NOT key isolation. See THREAT_MODEL.md.", flush=True)
    HTTPServer(("127.0.0.1", 8787), H).serve_forever()