- python -m src.tools.sym_demo

- cd out_ct
- python -m http.server 8000

- hostname -I

- Attack
- curl http://127.0.0.1:8000/ct.json -s | head -n 5
- python -m src.attacks.attacker_fetch_and_crack --base-url "http://10.1.33.104:8000"
- python -m src.attacks.attacker_fetch_and_crack --ct-path "/home/lakshay-baijal/IIIT_Hyderabad_CSIS/Semester_3/RIS/Project/Implementation/out_ct/ct.json" --shares-dir "/home/lakshay-baijal/IIIT_Hyderabad_CSIS/Semester_3/RIS/Project/Implementation/out_ct/shares"

- python -m src.tools.aa_demo
- python -m src.tools.tskt_demo
- python -m src.tools.multi_aa_encrypt_demo

- python -m src.tools.share_vault_pack \
  --in-ct out_multi_ct/ct_multi.json \
  --vault server_vault/vault.json \
  --out-ct out_multi_ct/ct_multi_stripped.json

- python -m src.edge.predecrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --out out_multi_ct/pre_token.json

- python -m src.tools.user_finish_decrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --token out_multi_ct/pre_token.json \
  --out out_multi_ct/decrypted.txt

- python -m src.edge.pretransform_elgamal \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --registry edge_registry/user_pub.json \
  --out out_multi_ct/transform_token.json

- python -m src.tools.user_finish_transform_decrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --token out_multi_ct/transform_token.json \
  --usersecret edge_registry/user_secret_demo.json \
  --out out_multi_ct/decrypted_transform.txt

- python -m src.tools.hierarchy_demo

- python -m src.tools.hierarchical_encrypt_demo

- python -m src.tools.hierarchical_full_chain_demo

- python -m src.tools.hierarchical_attack_tests

- python -m src.tools.share_vault_pack \
  --in-ct out_hier_ct/ct_hier.json \
  --vault server_vault/vault_hier.json \
  --out-ct out_hier_ct/ct_hier_stripped.json

- source venv/bin/activate

- echo "I am a good boy" > upload_demo.txt

- python -m src.tools.multi_aa_encrypt_demo

- python -m src.tools.share_vault_pack \
  --in-ct out_multi_ct/ct_multi.json \
  --vault server_vault/vault.json \
  --out-ct out_multi_ct/ct_multi_stripped.json

- python -m src.edge.predecrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --out out_multi_ct/pre_token.json


## Demo Mode

- ./multi_aa_encrypt_file.sh upload_demo.txt
- ./pack_vault_and_strip.sh
- ./ea_predecrypt.sh
- ./user_finish_decrypt_and_present.sh upload_demo.txt
