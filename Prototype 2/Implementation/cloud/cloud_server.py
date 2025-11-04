from utils.aes_util import gen_sym_key, aes_encrypt, aes_decrypt
from utils.ecc_util import verify_signature
import json

class CloudServer:
    def __init__(self, required_attrs):
        """
        required_attrs: list of attributes that must be present & valid.
        Example: ["dept:power", "role:engineer"]
        """
        self.required = required_attrs
        print(f"\n[Cloud] Initialized with policy: {self.required}")

    def verify_access(self, user_certs, authority_pubkeys):
        """
        user_certs: list of cert dicts like {"payload": {...}, "signature": "..."}
        authority_pubkeys: { issuer_name: public_key_object }
        returns (ok: bool, verified_attrs: list[str])
        """
        verified = []
        print("\n[Cloud] Verifying user certificates...")
        for cert in user_certs:
            payload = cert["payload"]
            issuer = payload["issued_by"]
            if issuer not in authority_pubkeys:
                print(f"  • Skipping: unknown issuer '{issuer}'")
                continue
            msg = json.dumps(payload).encode()
            sig_b64 = cert["signature"]
            ok = verify_signature(authority_pubkeys[issuer], msg, sig_b64)
            print(f"  • Cert attr='{payload['attribute']}', issuer='{issuer}' → valid={ok}")
            if ok:
                verified.append(payload["attribute"])

        need = set(self.required)
        have = set(verified)
        print(f"\n[Cloud] Verified attributes: {sorted(have)}")
        print(f"[Cloud] Required policy:  {sorted(need)}")
        return need.issubset(have), sorted(verified)

    def grant_access(self, user_certs, authority_pubkeys):
        """
        If policy satisfied → show AES key, ciphertext, tag, and decrypted plaintext.
        """
        ok, _ = self.verify_access(user_certs, authority_pubkeys)
        if not ok:
            print("\n[Cloud] ❌ Access Denied — missing/invalid attributes.")
            return None

        print("\n[Cloud] ✅ Policy satisfied. Proceeding to encrypt protected data...")
        key = gen_sym_key()
        secret = b"Confidential Industrial IoT Data (from Cloud)"
        enc = aes_encrypt(key, secret)
        pt = aes_decrypt(key, enc)
        print("\n[Cloud] ✅ Access Granted. Decrypted payload delivered to user.")
        return pt.decode(errors="ignore")
