# src/tools/hierarchy_demo.py
# Demonstrates RootAuthority delegation to multiple SubAuthorities.

from src.aa.hierarchy import RootAuthority
from pprint import pprint

def demo():
    # Create Root Authority
    RA = RootAuthority()

    # Create SubAuthorities with their attribute domains
    SA_Finance = RA.delegate_sub_authority("SA_Finance", ["attrA", "attrB"])
    SA_IT = RA.delegate_sub_authority("SA_IT", ["attrC", "attrD"])
    SA_HR = RA.delegate_sub_authority("SA_HR", ["attrE"])

    print("=== Hierarchy Structure ===")
    pprint(RA.describe_hierarchy())

    print("\nRoot P_pub (first 40 hex):", RA.get_public_params().P_root_bytes.hex()[:40])

    print("\nSubAuthorities created:")
    for sa_name, sa in RA.sub_authorities.items():
        print(f"  {sa_name} -> P_pub: {sa.P_pub.x}, Attributes: {sa.attributes}")

if __name__ == "__main__":
    demo()
