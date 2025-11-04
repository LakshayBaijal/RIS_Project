from utils.ecc_util import generate_ecc_keypair, sign_message, verify_signature
import json

class Authority:
    def __init__(self, name: str):
        self.name = name
        self.private_key, self.public_key = generate_ecc_keypair()
        print(f"[Authority: {self.name}] Key pair generated ✅")

    def issue_attribute(self, user_id: str, attribute: str):
        """Create an attribute certificate for a user."""
        payload = {
            "user_id": user_id,
            "attribute": attribute,
            "issued_by": self.name
        }
        sig = sign_message(self.private_key, json.dumps(payload).encode())
        cert = {"payload": payload, "signature": sig}
        print(f"[Authority: {self.name}] Issued attribute '{attribute}' to {user_id}\n")
        return cert

    def verify_attribute(self, cert: dict) -> bool:
        """Verify a received attribute certificate."""
        msg = json.dumps(cert["payload"]).encode()
        valid = verify_signature(self.public_key, msg, cert["signature"])
        print(f"[Authority: {self.name}] Verification of '{cert['payload']['attribute']}': {valid}")
        return valid
