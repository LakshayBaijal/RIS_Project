# authority/authority_server.py
"""
Authority Server Module
Each authority generates its own ECC key pair and signs user attributes.
These signed attributes act as 'attribute certificates' for CP-ABE-like logic.
"""

import json
from utils.ecc_util import generate_ecc_keypair, sign_message, verify_signature, serialize_public_key, serialize_private_key

class Authority:
    def __init__(self, name: str):
        self.name = name
        self.private_key, self.public_key = generate_ecc_keypair()
        print(f"[Authority: {self.name}] Key pair generated ✅")

    def issue_attribute(self, user_id: str, attribute: str):
        """
        Issues a signed certificate (JSON object) for a user attribute.
        """
        payload = {
            "user_id": user_id,
            "attribute": attribute,
            "issued_by": self.name
        }
        message_bytes = json.dumps(payload).encode()
        signature = sign_message(self.private_key, message_bytes)

        cert = {
            "payload": payload,
            "signature": signature.hex()
        }
        print(f"[Authority: {self.name}] Issued attribute '{attribute}' for {user_id}")
        return cert

    def verify_attribute(self, cert: dict) -> bool:
        """
        Verifies a certificate's signature using this authority's public key.
        """
        payload_bytes = json.dumps(cert["payload"]).encode()
        signature_bytes = bytes.fromhex(cert["signature"])
        valid = verify_signature(self.public_key, payload_bytes, signature_bytes)
        print(f"[Authority: {self.name}] Verification of '{cert['payload']['attribute']}': {valid}")
        return valid

    def export_public_key(self):
        return serialize_public_key(self.public_key).decode()

    def export_private_key(self):
        return serialize_private_key(self.private_key).decode()
