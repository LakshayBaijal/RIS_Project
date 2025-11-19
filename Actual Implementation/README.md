# RIS Project
## Secure Multi Authority Hierarchical Access Control for Industrial IoT using ECC-Based CP-ABE

### Execution
https://github.com/user-attachments/assets/3fbe36ed-da62-4d7f-add3-206eeeeae9ae

### Link to Report
```br
https://github.com/LakshayBaijal/RIS_Project/blob/main/RIS_Project.pdf
```
```br
https://github.com/LakshayBaijal/RIS_Project/blob/main/PPT.pdf
```

### Directory Structure
```br
.
├── attacker_demo_presentation.sh
├── attacker_local_output
│   ├── log.txt
│   └── recovered.txt
├── attacker_local.sh
├── attacker_presentation_with_save.sh
├── benchmark_performance_graphs.py
├── demo.txt
├── ea_predecrypt.sh
├── edge_registry
│   ├── user_pub.json
│   └── user_secret_demo.json
├── Image_Upload.png
├── local_rehearse_demo.sh
├── multi_aa_encrypt_file.sh
├── normal_access_demo.sh
├── one_click_multi_aa_upload_demo.sh
├── out_ct
│   ├── ct.json
│   └── shares
│       ├── share_1.json
│       ├── share_2.json
│       ├── share_3.json
│       ├── share_4.json
│       └── share_5.json
├── out_hier_ct
│   ├── ct_hier.json
│   ├── ct_hier_stripped.json
│   ├── transform_revoked.json
│   └── transform_token_fake.json
├── out_multi_ct
│   ├── ct_multi.json
│   ├── ct_multi_stripped.json
│   ├── decrypted_transform.txt
│   ├── decrypted.txt
│   ├── pre_token.json
│   └── transform_token.json
├── pack_vault_and_strip.sh
├── performance_graph.png
├── performance_log.csv
├── README.md
├── requirements.txt
├── server_vault
│   ├── revocation.json
│   ├── vault_hier.json
│   └── vault.json
├── src
│   ├── aa
│   │   ├── authority.py
│   │   ├── hierarchy.py
│   │   └── __pycache__
│   │       ├── authority.cpython-312.pyc
│   │       └── hierarchy.cpython-312.pyc
│   ├── attacks
│   │   ├── attacker_fetch_and_crack.py
│   │   └── __pycache__
│   │       └── attacker_fetch_and_crack.cpython-312.pyc
│   ├── crypto
│   │   ├── ecc.py
│   │   ├── __pycache__
│   │   │   ├── ecc.cpython-312.pyc
│   │   │   └── sym.cpython-312.pyc
│   │   └── sym.py
│   ├── edge
│   │   ├── edge_stub.py
│   │   ├── predecrypt.py
│   │   ├── pretransform_elgamal.py
│   │   └── __pycache__
│   │       ├── edge_stub.cpython-312.pyc
│   │       ├── predecrypt.cpython-312.pyc
│   │       └── pretransform_elgamal.cpython-312.pyc
│   ├── encrypt
│   │   ├── multi_aa_encryptor.py
│   │   └── __pycache__
│   │       └── multi_aa_encryptor.cpython-312.pyc
│   ├── lsss
│   │   ├── __pycache__
│   │   │   └── shamir.cpython-312.pyc
│   │   └── shamir.py
│   ├── tools
│   │   ├── aa_demo.py
│   │   ├── encryptor_demo.py
│   │   ├── hierarchical_attack_tests.py
│   │   ├── hierarchical_encrypt_demo.py
│   │   ├── hierarchical_full_chain_demo.py
│   │   ├── hierarchy_demo.py
│   │   ├── multi_aa_encrypt_demo.py
│   │   ├── __pycache__
│   │   │   ├── aa_demo.cpython-312.pyc
│   │   │   ├── encryptor_demo.cpython-312.pyc
│   │   │   ├── hierarchical_attack_tests.cpython-312.pyc
│   │   │   ├── hierarchical_encrypt_demo.cpython-312.pyc
│   │   │   ├── hierarchy_demo.cpython-312.pyc
│   │   │   ├── multi_aa_encrypt_demo.cpython-312.pyc
│   │   │   ├── revocation_rekey_demo.cpython-312.pyc
│   │   │   ├── shamir_demo.cpython-312.pyc
│   │   │   ├── share_vault_pack.cpython-312.pyc
│   │   │   ├── sym_demo.cpython-312.pyc
│   │   │   ├── tskt_demo.cpython-312.pyc
│   │   │   ├── user_finish_decrypt.cpython-312.pyc
│   │   │   ├── user_finish_transform_decrypt.cpython-312.pyc
│   │   │   └── victim_export.cpython-312.pyc
│   │   ├── revocation_rekey_demo.py
│   │   ├── shamir_demo.py
│   │   ├── share_vault_pack.py
│   │   ├── sym_demo.py
│   │   ├── tskt_demo.py
│   │   ├── user_finish_decrypt.py
│   │   ├── user_finish_transform_decrypt.py
│   │   └── victim_export.py
│   └── user
│       ├── __pycache__
│       │   └── user.cpython-312.pyc
│       └── user.py
├── upload_benchmark_1000KB.txt
├── upload_benchmark_100KB.txt
├── upload_benchmark_10KB.txt
├── upload_benchmark_1KB.txt
├── upload_benchmark_500KB.txt
├── upload_demo.txt
├── user_finish_decrypt_and_present.sh
├── user_interactive_fetch.sh
├── victim_demo_presentation.sh
└── victim_server_presentable.py
```

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

# Theory
▶ The Industrial Internet of Things (IIoT) connects thousands of devices
and sensors that continuously share sensitive operational data.

▶ Ensuring secure, fine-grained, and scalable access control is a
major challenge due to limited device resources.

### Traditional solutions:

▶ Centralized access control → single point of failure.

▶ Pairing-based CP-ABE → computationally expensive for embedded
nodes.

### Our approach:

▶ A lightweight ECC-based Multi-Authority CP-ABE system.

▶ Integrates a hierarchical trust model (Root Authority →
Sub-Authorities → AAs).

▶ Employs an Edge Authority (EA) for partial decryption assistance
without compromising privacy.

▶ Designed specifically for resource-constrained IIoT deployments.

## Motivation
▶ Challenge 1: Heavy Computation in IoT Devices

Most ABE systems rely on pairing-based cryptography, requiring high
CPU cycles and memory — unsuitable for embedded systems.

▶ Challenge 2: Centralized Trust Model

A single authority managing all attributes leads to bottlenecks, privacy
risks, and poor scalability across organizations.

▶ Challenge 3: Real-Time Decryption Demand

Industrial sensors need quick access verification without offloading full
decryption load to cloud or central servers.

▶ Use Elliptic Curve Cryptography (ECC) for efficiency — smaller
keys, faster scalar operations.

▶ Employ Multi-Authority (MA) hierarchy to distribute attribute
management.

▶ Introduce Edge-Assisted Decryption to offload heavy
computation securely.

## Technology Stack & Tools
Programming Language and Environment:

▶ Implemented entirely in Python 3.12.

▶ Virtual environment managed using venv.

### Core Cryptographic Libraries:

▶ ECPy — for Elliptic Curve Cryptography on secp256r1.

▶ cryptography — AES-GCM encryption and decryption.

▶ hashlib — SHA-256 for key derivation.

### Mathematical Components:

▶ Shamir’s Secret Sharing implemented for attribute-based threshold enforcement.

▶ Elliptic curve arithmetic for scalar multiplication and point addition.

### Data Handling & Analysis:

▶ numpy, pandas, and matplotlib for performance benchmarks.

▶ networkx for future access-structure visualization.

### Execution Scripts:

▶ Automated demo: one click multi aa upload demo.sh

▶ Performance test: benchmarks/perf benchmark.py

### Cryptosystem Overview: Motivation & Design Choice

Why ECC-based Cryptosystem?

▶ Traditional ABE schemes rely on pairing-based cryptography (e.g., bilinear
maps).

▶ Pairings are computationally heavy for IoT or edge devices.

▶ Elliptic Curve Cryptography (ECC) offers equivalent security at smaller key
sizes:

▶ 256-bit ECC 3072-bit RSA in strength.

▶ Fewer modular multiplications → faster and energy-efficient.

Why Multi-Authority Hierarchy?

▶ Prevents single-point trust failure.

▶ Each Sub-Authority manages distinct attributes (domain-wise, e.g., Finance, IT).

▶ Enables scalable and distributed key management.

Cryptographic Components Used:

1. ECC (secp256r1) — public key generation, ElGamal transform.
2. AES-GCM — fast symmetric encryption of data.
3. Shamir’s Secret Sharing — enforces attribute-based access threshold.
4. SHA-256 — deterministic key derivation from EC points.
