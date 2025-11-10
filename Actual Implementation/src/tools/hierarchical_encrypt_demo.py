# src/tools/hierarchical_encrypt_demo.py
# Hierarchical multi-level encryption demo:
# - Build RootAuthority -> SubAuthorities (Finance, IT, HR)
# - Define a policy using namespaced attributes (e.g., "SA_Finance.attrA", "SA_IT.attrC")
# - Construct owner map (namespaced_attr -> SA name)
# - Call the existing multi-authority encryptor to produce a CT

from pathlib import Path
import json

from src.aa.hierarchy import RootAuthority
from src.encrypt.multi_aa_encryptor import encrypt_file_multi_aa

def build_hierarchy():
    RA = RootAuthority()
    SA_Finance = RA.delegate_sub_authority("SA_Finance", ["attrA", "attrB"])
    SA_IT = RA.delegate_sub_authority("SA_IT", ["attrC", "attrD"])
    SA_HR = RA.delegate_sub_authority("SA_HR", ["attrE"])
    return RA

def namespaced_owner_map(RA):
    """
    Build a mapping from 'SA_X.attrY' -> 'SA_X' for all attributes managed by each SA.
    """
    mapping = {}
    for sa_name, sa in RA.sub_authorities.items():
        for attr in sa.attributes:
            mapping[f"{sa_name}.{attr}"] = sa_name
    return mapping

def demo():
    # 1) Build hierarchy
    RA = build_hierarchy()

    # 2) Build owner map for namespaced attributes
    owner_map = namespaced_owner_map(RA)

    # 3) Define hierarchical policy (simple AND over two SAs)
    #    You can vary this list and threshold to test different policies
    attrs_required = ["SA_Finance.attrA", "SA_IT.attrC", "SA_Finance.attrB"]
    threshold = 3  # require all three; set to 2 to allow any 2 of them

    # 4) Encrypt some plaintext
    plaintext = b"Hierarchical MA-CP-ABE demo: Finance+IT policy satisfied."
    out_ct = "out_hier_ct/ct_hier.json"

    # 5) Run encryption (reuses your existing encryptor)
    ct_path = encrypt_file_multi_aa(
        plaintext_bytes=plaintext,
        attrs_ordered=attrs_required,   # pass namespaced attribute labels directly
        aa_owner_map=owner_map,         # maps each namespaced attr to its SubAuthority
        threshold=threshold,
        out_ct_path=out_ct
    )

    print("Wrote CT to:", ct_path)

    # 6) Show a concise summary
    ct = json.load(open(ct_path, "r"))
    print("CT meta:", ct["meta"])
    print("Shares:")
    for attr, info in ct["shares"].items():
        print(f"  {attr} -> owner={info['owner']}, index={info['index']}, share_hex(prefix)={info['share_hex'][:10]}")

if __name__ == "__main__":
    demo()
