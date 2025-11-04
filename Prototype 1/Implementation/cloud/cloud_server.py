# cloud/cloud_server.py
"""
Cloud Server Module
Simulates a cloud verifying user attributes before decrypting or granting data access.
"""

import json
from utils.aes_util import gen_sym_key, aes_encrypt, aes_decrypt
from authority.authority_server import Authority

class CloudServer:
    def __init__(self, access_policy: list):
        """
        Example access_policy = ["dept:power", "role:engineer"]
        means both attributes are required.
        """
        self.policy = access_policy
        self.secret_key = gen_sym_key()  # AES symmetric key
        self.data = aes_encrypt(self.secret_key, b"Confidential Energy Grid Data.")
        print(f"[Cloud] Initialized with access policy: {self.policy}")

    def verify_access(self, user_certs: list, authority_pubkeys: dict):
        """
        Verify that all required attributes are present and signed by trusted authorities.
        """
        from utils.ecc_util import verify_signature

        verified_attrs = []
        for cert in user_certs:
            payload = cert["payload"]
            attr = payload["attribute"]
            issuer = payload["issued_by"]
            if issuer not in authority_pubkeys:
                continue
            pubkey = authority_pubkeys[issuer]
            sig = bytes.fromhex(cert["signature"])
            if verify_signature(pubkey, json.dumps(payload).encode(), sig):
                verified_attrs.append(attr)

        print(f"[Cloud] Verified attributes: {verified_attrs}")
        return all(req in verified_attrs for req in self.policy)

    def grant_access(self, user_certs: list, authority_pubkeys: dict):
        """
        Grants access if user meets the policy.
        """
        if self.verify_access(user_certs, authority_pubkeys):
            pt = aes_decrypt(self.secret_key, self.data)
            print("[Cloud] ✅ Access granted!")
            return pt.decode()
        else:
            print("[Cloud] ❌ Access denied — missing attributes.")
            return None
