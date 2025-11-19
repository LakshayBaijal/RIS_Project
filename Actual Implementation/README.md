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
The Industrial Internet of Things (IIoT) connects thousands of devices
and sensors that continuously share sensitive operational data.

Ensuring secure, fine-grained, and scalable access control is a
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

### Why ECC-based Cryptosystem?

▶ Traditional ABE schemes rely on pairing-based cryptography (e.g., bilinear
maps).

▶ Pairings are computationally heavy for IoT or edge devices.

▶ Elliptic Curve Cryptography (ECC) offers equivalent security at smaller key
sizes:

▶ 256-bit ECC 3072-bit RSA in strength.

▶ Fewer modular multiplications → faster and energy-efficient.

### Why Multi-Authority Hierarchy?

▶ Prevents single-point trust failure.

▶ Each Sub-Authority manages distinct attributes (domain-wise, e.g., Finance, IT).

▶ Enables scalable and distributed key management.

### Cryptographic Components Used:

1. ECC (secp256r1) — public key generation, ElGamal transform.
2. AES-GCM — fast symmetric encryption of data.
3. Shamir’s Secret Sharing — enforces attribute-based access threshold.
4. SHA-256 — deterministic key derivation from EC points.

### Cryptosystem Overview: ECC and Key Generation

### Elliptic Curve Cryptography (ECC):

▶ Curve used: secp256r1.

▶ Group operation: point addition and scalar multiplication over finite field.

▶ Base point G acts as generator for key derivation.

### Key Generation:

Private key: x ∈R [1, n − 1],

Public key: P = xG

▶ Each authority (AA) and user generates ECC key pairs.

▶ Root Authority distributes trust by delegating xi values to sub-authorities.

### Advantages over RSA/Pairing Schemes:

▶ Smaller key sizes reduce computation time and bandwidth.

▶ Compatible with lightweight IoT processors.

▶ Secure under the Elliptic Curve Discrete Logarithm Problem (ECDLP).

## Implementation:

▶ ecpy.curves.Curve.get curve(’secp256r1’)

▶ Functions: scalar mul(k,P), point add(P,Q), hash to int(data).

Cryptosystem Overview: AES-GCM and Key

## Derivation

### Why AES-GCM?

▶ Provides both confidentiality and integrity.

▶ Authenticated encryption mode prevents tampering.


▶ GCM is faster and parallelizable compared to CBC or CFB modes.

### Key Derivation from ECC:

▶ Instead of random AES keys, derive it deterministically from EC point sG.


K = SHA256(point to bytes(sG))

▶ Ensures both encryptor and decryptor obtain identical AES key using shared scalar s.


### Encryption Process:

1. Choose random scalar s.

2. Derive AES key K from sG.

3. Encrypt plaintext using:

AESGCM(K ).encrypt(nonce, plaintext)

4. Output {nonce, ct, P bytes b64}.

### Decryption:

▶ Compute same sG at receiver side.

▶ Re-derive K = H(sG) and decrypt using AES-GCM.

Cryptosystem Overview: Shamir’s Secret Sharing &
ElGamal Transform

### Shamir’s Secret Sharing (SSS):

▶ Used to distribute scalar s among n attributes.

▶ Secret polynomial: f (x) = s + a1 x + a2 x 2 + · · · + at−1 x t−1 .

▶ Each attribute receives a share (xi , f (xi )).

▶ Threshold property: any t shares can reconstruct s.

### Why Shamir’s Scheme?

▶ Linear operations — easy to implement over Zp .

▶ Supports dynamic threshold adjustment (e.g., t = 3 of 5 attributes).

### ElGamal-Based Edge Transformation:

▶ Edge Authority (EA) helps decrypt without learning s.

C1 = rG,

C2 = sG + rDpub

▶ User derives:

sG = C2 − dC1

▶ This blinded transformation allows lightweight user decryption.

### Security:

▶ EA never learns d or K .

▶ Resistant to replay and collusion due to threshold reconstruction.

Workflow 1: Multi-Authority Encryption

1. Attribute Assignment: Each attribute (e.g., attrA, attrC) is managed by its
own Attribute Authority (AA).

2. Secret Sharing: A random scalar s is generated and divided into n shares using
Shamir’s (n, t) scheme.

3. Share Distribution: Each share is tagged with its corresponding attribute and
owner AA.

4. Ciphertext Generation:

▶ Compute P = sG and derive AES key K = H(P).

▶ Encrypt data with AES-GCM → produces (nonce, ct).

5. Vault Creation: All attribute shares are stored in a secure vault.json.

### Workflow 2: Edge-Assisted Decryption (EA Transform)


1. EA Pre-Decrypt:

▶ EA verifies user’s authorized attributes.

▶ Fetches corresponding shares from vault.json.

▶ Reconstructs or blinds s (depending on threshold policy).

2. ElGamal-Based Transformation:

C1 = rG,

C2 = sG + rDpub

▶ EA sends (C1 , C2 ) as a transform token to the user.

3. User Final Decryption:

sG = C2 − dC1 ,

K = H(sG)

▶ User derives K and decrypts AES-GCM ciphertext to recover
original data.

## Threat Model & Security Mechanisms


1. Collusion Attack:

▶ Unauthorized users may try to combine their shares.

▶ Prevented by Shamir’s threshold t: fewer than t shares reveal nothing.

2. Malicious Edge Authority:

▶ EA cannot recover AES key since it lacks user secret d.

▶ ElGamal transformation ensures s remains hidden.

3. Key Exposure Attack:

▶ Even if transformed keys (TSKs) are leaked, they depend on d.

4. Integrity & Authenticity:

▶ AES-GCM provides built-in authentication.

▶ Any ciphertext tampering causes decryption failure.


## Performance & Results


### Benchmark Setup:

▶ Measured runtime for ECC scalar multiplication and AES-GCM encryption.

▶ System: Intel i7 CPU, Python 3.12, ECPy (secp256r1).

### Results:

▶ ECC operations scale linearly with the number of keys (up to 1000 ops).

▶ AES-GCM overhead is minimal (<2 ms for 1 MB files).

▶ Our ECC-based scheme reduces total computation by 60–70% vs pairing-based
CP-ABE.

- ECC vs AES-GCM runtime on increasing workload.
<img width="927" height="606" alt="image" src="https://github.com/user-attachments/assets/1b2db47b-6cd6-4649-a3ee-b7a433bd19dc" />

- ECC CP-ABE Performance on IIoT Simulation — Measured encryption, edge pre-decrpytion
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/eee7195d-88bf-4b6d-8915-8a763bd960ca" />


## Conclusion & Future Work

### Summary:

▶ Implemented an ECC-based Multi-Authority Hierarchical
CP-ABE system.

▶ Enabled lightweight access control for Industrial IoT.

▶ Edge-assisted decryption offloads computation from constrained

devices.

### Future Research Directions:

▶ Efficient attribute revocation and key updates.

▶ Integration with real IoT hardware (e.g., Raspberry Pi).

▶ Lattice-based or post-quantum cryptography for resilience.

▶ Formal proofs of security under standard assumptions.

