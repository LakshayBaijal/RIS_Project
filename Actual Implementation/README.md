# RIS Project
## Secure Multi Authority Hierarchical Access Control for Industrial IoT using ECC-Based CP-ABE

### Execution
https://github.com/user-attachments/assets/3fbe36ed-da62-4d7f-add3-206eeeeae9ae



### Demo Commands
```br
./multi_aa_encrypt_file.sh upload_demo.txt
```
```br
./pack_vault_and_strip.sh
```
```br
./ea_predecrypt.sh
```
```br
./user_finish_decrypt_and_present.sh upload_demo.txt
```
```br
python benchmark_performance_graphs.py
```

### Uploading text to attack
```br
python -m src.tools.victim_export --infile upload_demo.txt --outdir out_ct --n 5 --t 3
```
### Attacker suceeded different terminal
```br
python3 victim_server_presentable.py --dir out_ct --port 8000
```
```br
./attacker_local.sh 8000
less attacker_local_output/recovered.txt
```

### Attacker failed different terminal

```br
python3 victim_server_presentable.py --dir out_multi_ct --port 8000
```
```br
./attacker_local.sh 8000
```
```br
less attacker_local_output/log.txt
```

### Other Commands
```br
python -m src.tools.sym_demo
```
```br
cd out_ct
```
```br
python -m http.server 8000
```
```br
hostname -I
```

- Attack
```br
curl http://127.0.0.1:8000/ct.json -s | head -n 5
python -m src.attacks.attacker_fetch_and_crack --base-url "http://10.1.33.104:8000"
python -m src.attacks.attacker_fetch_and_crack --ct-path "/home/lakshay-baijal/IIIT_Hyderabad_CSIS/Semester_3/RIS/Project/Implementation/out_ct/ct.json" --shares-dir "/home/lakshay-baijal/IIIT_Hyderabad_CSIS/Semester_3/RIS/Project/Implementation/out_ct/shares"
```
```br
python -m src.tools.aa_demo
```
```br
python -m src.tools.tskt_demo
```
```br
python -m src.tools.multi_aa_encrypt_demo
```
```br

python -m src.tools.share_vault_pack \
  --in-ct out_multi_ct/ct_multi.json \
  --vault server_vault/vault.json \
  --out-ct out_multi_ct/ct_multi_stripped.json
```
```br
python -m src.edge.predecrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --out out_multi_ct/pre_token.json
```
```br
python -m src.tools.user_finish_decrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --token out_multi_ct/pre_token.json \
  --out out_multi_ct/decrypted.txt
```
```br

python -m src.edge.pretransform_elgamal \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --registry edge_registry/user_pub.json \
  --out out_multi_ct/transform_token.json
```
```br

python -m src.tools.user_finish_transform_decrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --token out_multi_ct/transform_token.json \
  --usersecret edge_registry/user_secret_demo.json \
  --out out_multi_ct/decrypted_transform.txt
```
```br
python -m src.tools.hierarchy_demo
```
```br
python -m src.tools.hierarchical_encrypt_demo
```
```br
python -m src.tools.hierarchical_full_chain_demo
```
```br
python -m src.tools.hierarchical_attack_tests
```
```br
python -m src.tools.share_vault_pack \
  --in-ct out_hier_ct/ct_hier.json \
  --vault server_vault/vault_hier.json \
  --out-ct out_hier_ct/ct_hier_stripped.json
```
```br

python -m src.tools.multi_aa_encrypt_demo
```
```br
python -m src.tools.share_vault_pack \
  --in-ct out_multi_ct/ct_multi.json \
  --vault server_vault/vault.json \
  --out-ct out_multi_ct/ct_multi_stripped.json
```
```br
python -m src.edge.predecrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --out out_multi_ct/pre_token.json
```
