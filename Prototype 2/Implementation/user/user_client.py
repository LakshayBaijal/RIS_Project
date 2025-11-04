from utils.ecc_util import generate_ecc_keypair

class User:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.private_key, self.public_key = generate_ecc_keypair()
        self.attributes = []
        print(f"[User: {self.user_id}] ECC key pair generated ✅")

    def receive_attribute(self, cert: dict, authority):
        """Accept an attribute certificate if verified."""
        if authority.verify_attribute(cert):
            attr = cert["payload"]["attribute"]
            self.attributes.append(attr)
            print(f"[User: {self.user_id}] Attribute '{attr}' verified & stored ✅")

    def show_attributes(self):
        print(f"\n[+] Attributes for {self.user_id}: {self.attributes}")
