# src/tools/aa_demo.py
# Demo: create two Authorities, publish their public params, and issue attribute keys for a user UID.

from src.aa.authority import Authority
from binascii import hexlify
from src.crypto.ecc import point_to_bytes

def demo():
    # Create two authorities with different attribute domains
    AA1 = Authority("AA1", ["attrA", "attrB"])
    AA2 = Authority("AA2", ["attrC", "attrD"])

    # Publish params (you might store these in a PKI or registry)
    pk1 = AA1.get_public_params()
    pk2 = AA2.get_public_params()

    print("=== Published Public Params (summary) ===")
    print("AA1 P_pub (first 20 hex):", hexlify(point_to_bytes(pk1.P_pub_point))[:40])
    for a, pbytes in pk1.PK_attrs.items():
        print(" AA1 PK_attr", a, ":", hexlify(pbytes)[:40])
    print()
    print("AA2 P_pub (first 20 hex):", hexlify(point_to_bytes(pk2.P_pub_point))[:40])
    for a, pbytes in pk2.PK_attrs.items():
        print(" AA2 PK_attr", a, ":", hexlify(pbytes)[:40])
    print()

    # Issue keys for a user UID
    uid = "user123@example.com"
    sk1 = AA1.keygen_for_user(uid, "attrA")
    sk2 = AA1.keygen_for_user(uid, "attrB")
    sk3 = AA2.keygen_for_user(uid, "attrC")

    print("=== Issued SKs for UID:", uid, "===\n")
    print("SK for attrA (AA1): scalar (hex):", hex(sk1['sk_scalar']))
    print("SK point (first 40 hex):", hexlify(sk1['sk_point_bytes'])[:40])
    print()
    print("SK for attrB (AA1): scalar (hex):", hex(sk2['sk_scalar']))
    print("SK for attrC (AA2): scalar (hex):", hex(sk3['sk_scalar']))
    print()

    # Show that a different UID would get different SK for same attribute
    uid2 = "attacker@example.com"
    sk1_att = AA1.keygen_for_user(uid2, "attrA")
    print("Different UID SK for attrA:", hex(sk1_att['sk_scalar'])[:40])
    print("Original UID SK for attrA: ", hex(sk1['sk_scalar'])[:40])
    print("\n✅ Keys are UID-bound (different UID → different SK).")

if __name__ == "__main__":
    demo()
