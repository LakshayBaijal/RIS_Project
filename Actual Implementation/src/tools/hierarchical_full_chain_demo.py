# src/tools/hierarchical_full_chain_demo.py
# Runs full end-to-end test for hierarchical MA-HCP-ABE chain:
#   Encryption → Vault → EA Transform → User Final Decrypt

import json
from pathlib import Path
from subprocess import run

def sh(cmd):
    print(f"\n$ {cmd}")
    run(cmd, shell=True, check=True)

def main():
    # --- STEP 1: ensure ciphertext exists (from hierarchical_encrypt_demo)
    ct_path = Path("out_hier_ct/ct_hier.json")
    if not ct_path.exists():
        print("[!] Hierarchical CT not found. Run hierarchical_encrypt_demo first.")
        return

    # --- STEP 2: pack into vault
    vault_path = Path("server_vault/vault_hier.json")
    ct_stripped = Path("out_hier_ct/ct_hier_stripped.json")
    sh(f"python -m src.tools.share_vault_pack --in-ct {ct_path} --vault {vault_path} --out-ct {ct_stripped}")

    # --- STEP 3: EA pre-transform (privacy-preserving)
    token_path = Path("out_hier_ct/transform_token_hier.json")
    attrs = "SA_Finance.attrA,SA_IT.attrC,SA_Finance.attrB"
    sh(f"python -m src.edge.pretransform_elgamal --ct {ct_stripped} --vault {vault_path} "
       f"--uid user123@example.com --attrs {attrs} "
       f"--registry edge_registry/user_pub.json --out {token_path}")

    # --- STEP 4: User final decryption
    decrypted_path = Path("out_hier_ct/decrypted_hier.txt")
    sh(f"python -m src.tools.user_finish_transform_decrypt --ct {ct_stripped} "
       f"--token {token_path} --usersecret edge_registry/user_secret_demo.json "
       f"--out {decrypted_path}")

    # --- STEP 5: Show final result
    pt = Path(decrypted_path).read_text(errors="replace")
    print("\n✅ HIERARCHICAL CHAIN COMPLETE.")
    print("Decrypted plaintext:\n", pt)

if __name__ == "__main__":
    main()
