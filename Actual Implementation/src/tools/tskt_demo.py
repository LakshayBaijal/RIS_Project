# src/tools/tskt_demo.py
# Demo tying Authorities (from earlier), User USK/TSK generation and EA storage usage.
# Run: python -m src.tools.tskt_demo

from src.aa.authority import Authority
from src.user.user import User
from src.edge.edge_stub import EdgeAuthorityStub
from binascii import hexlify
from src.crypto.ecc import point_to_bytes

def demo():
    # Create two Authorities and a user
    AA1 = Authority("AA1", ["attrA", "attrB"])
    AA2 = Authority("AA2", ["attrC"])

    uid = "user123@example.com"
    user = User(uid)

    # Authorities issue SKs to user for attributes
    sk_attrA = AA1.keygen_for_user(uid, "attrA")
    sk_attrB = AA1.keygen_for_user(uid, "attrB")
    sk_attrC = AA2.keygen_for_user(uid, "attrC")
    user_sks = [sk_attrA, sk_attrB, sk_attrC]

    print("User UID:", uid)
    print("User USK (private d) (first 12 hex):", hex(user.get_USK())[:12])
    print()

    # User computes TSKs and uploads to EA
    tsk_list = user.compute_TSKs(user_sks)
    ea = EdgeAuthorityStub()
    ea.store_tsk_for_uid(uid, tsk_list)
    print("TSKs stored at EA (first 20 hex of first tsk point):")
    for t in tsk_list:
        print(" -", t['attribute'], hexlify(t['tsk_point_bytes'])[:40])
    print()

    # EA attempts to recover SKs (should be impossible)
    ea_attempt = ea.attempt_recover_sk(uid)
    print("EA attempt to recover SKs (without user's d):", ea_attempt)
    print()

    # User pulls TSKs from EA and recovers SKs locally using d
    stored_tsks = ea.get_tsk_for_uid(uid)
    recovered_sks = user.recover_SKs_from_TSKs(stored_tsks)
    print("User recovered SK scalars (first 2 hex chars) from TSKs:")
    for r in recovered_sks:
        print(" -", r['attribute'], hex(r['sk_scalar'])[:12], hexlify(r['sk_point_bytes'])[:40])
    print("\n✅ Demo complete. EA cannot recover SKs without the user's secret d. User can recover SKs from stored TSKs.")

if __name__ == "__main__":
    demo()
