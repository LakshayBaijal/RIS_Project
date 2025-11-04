from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
import json, base64

class Authority:
    def __init__(self, name: str):
        self.name = name
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        print(f"[Authority: {self.name}] Key pair generated ✅")

    def issue_attribute(self, user_id: str, attribute: str):
        """Generate signed certificate for an attribute."""
        payload = {"user_id": user_id, "attribute": attribute, "issued_by": self.name}
        msg = json.dumps(payload).encode()
        sig = self.private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig)
        signature = base64.b16encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
        print(f"[Authority: {self.name}] Issued attribute '{attribute}' for {user_id}")
        return {"payload": payload, "signature": signature}

    def verify_attribute(self, cert):
        """Verify a received certificate."""
        payload = json.dumps(cert["payload"]).encode()
        raw = base64.b16decode(cert["signature"].encode())
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        sig = encode_dss_signature(r, s)
        try:
            self.public_key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
