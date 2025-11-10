# src/tools/multi_aa_encrypt_demo.py
# Demo: create AAs, publish their public params, then encrypt a file under a multi-authority attribute list.

from src.aa.authority import Authority
from src.encrypt.multi_aa_encryptor import encrypt_file_multi_aa
from pathlib import Path
import json

def demo():
    # Create two Authorities and attributes they control
    AA1 = Authority("AA1", ["attrA", "attrB"])
    AA2 = Authority("AA2", ["attrC", "attrD"])

    # Build attribute -> owner mapping (registry)
    aa_owner_map = {}
    for a in AA1.attributes:
        aa_owner_map[a] = AA1.name
    for a in AA2.attributes:
        aa_owner_map[a] = AA2.name

    # Attributes required by policy (simple AND of these attributes)
    attrs_required = ["attrA", "attrC", "attrB"]  # example order
    threshold = 3  # require all 3 shares; set lower to allow threshold behavior

    # plaintext
    demo_txt = b"This is a multi-authority encryption demo file."
    out_ct = "out_multi_ct/ct_multi.json"

    ct_path = encrypt_file_multi_aa(demo_txt, attrs_required, aa_owner_map, threshold, out_ct)
    print("Wrote CT to:", ct_path)

    # Show a brief summary of CT content
    ct = json.load(open(ct_path, "r"))
    print("CT meta:", ct["meta"])
    print("Share owners and indices:")
    for attr, info in ct["shares"].items():
        print(" ", attr, "owner:", info["owner"], "index:", info["index"], "share_hex(prefix):", info["share_hex"][:10])

if __name__ == "__main__":
    demo()
