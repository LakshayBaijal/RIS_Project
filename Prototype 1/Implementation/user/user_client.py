# user/user_client.py
"""
User Client Module
Each user holds ECC keys for encryption/decryption and stores signed attribute
certificates issued by multiple authorities.
"""

import json
from utils.ecc_util import generate_ecc_keypair, serialize_public_key, serialize_private_key
from authority.authority_server import Authority

class UserClient:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.private_key, self.public_key = generate_ecc_keypair()
        self.attributes = []  # list of verified certificates
        print(f"[User: {self.user_id}] ECC key pair generated ✅")

    def request_attribute(self, authority: Authority, attribute: str):
        """Requests and verifies an attribute certificate from a given authority."""
        cert = authority.issue_attribute(self.user_id, attribute)
        if authority.verify_attribute(cert):
            self.attributes.append(cert)
            print(f"[User: {self.user_id}] Attribute '{attribute}' verified & stored ✅")
        else:
            print(f"[User: {self.user_id}] Attribute '{attribute}' verification failed ❌")

    def list_attributes(self):
        """Lists all verified attributes currently held by this user."""
        return [c['payload']['attribute'] for c in self.attributes]

    def export_keys(self):
        """Returns a dict containing serialized keys (PEM format)."""
        return {
            "user_id": self.user_id,
            "public_key": serialize_public_key(self.public_key).decode(),
            "private_key": serialize_private_key(self.private_key).decode()
        }

    def export_attributes(self):
        """Returns all attribute certificates as JSON."""
        return json.dumps(self.attributes, indent=2)
