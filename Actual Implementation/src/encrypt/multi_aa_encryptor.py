# src/encrypt/multi_aa_encryptor.py
"""
Multi-Authority encryptor (simple AND policy).
Inputs:
 - plaintext bytes or path
 - attrs_ordered: list of attribute names (each attribute must be managed by some AA)
 - aa_registry: dict mapping attr -> (aa_name, aa_public_params_bytes)  (we only need attr->owner here)
 - n_shares = len(attrs_ordered)
 - threshold t (how many shares needed) — for simple AND set t = n_shares, or allow t < n_shares for thresholds
Outputs:
 - JSON file (CT) with AES-GCM ciphertext, P = s*G (base64), and per-attribute share entries:
    { "attribute": {"owner": "AA1", "index": i, "share_hex": "0x..." } }
This is a prototype: later we will bind shares to AAs more tightly and include AA public points in CT.
"""
import os, json, base64, random
from pathlib import Path
from hashlib import sha256

from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_encrypt
from src.lsss.shamir import split_secret

def encrypt_file_multi_aa(plaintext_bytes: bytes, attrs_ordered: list, aa_owner_map: dict, threshold: int, out_ct_path: str):
    """
    plaintext_bytes: bytes
    attrs_ordered: ["attrA", "attrB", "attrC", ...] - order matters for share assignment
    aa_owner_map: { "attrA": "AA1", "attrB": "AA2", ... }
    threshold: t (int)
    out_ct_path: output path for JSON CT
    """
    if threshold < 1 or threshold > len(attrs_ordered):
        raise ValueError("threshold must be between 1 and number of attributes")

    # 1) symmetric key generation: choose random s scalar and compute P = s*G
    # derive AES key from point P
    curve = None
    # choose s
    from ecpy.curves import Curve
    curve = Curve.get_curve('secp256r1')
    s = random.randrange(1, curve.order)
    P = scalar_mul(s)
    P_bytes = point_to_bytes(P)
    key = derive_key_from_point(P_bytes)

    # 2) AES encrypt
    aes = aes_encrypt(key, plaintext_bytes)

    # 3) Split secret s into shares for the attributes
    shares = split_secret(s, len(attrs_ordered), threshold)  # list of (i, share_int)

    # 4) Map shares to attributes in order
    share_map = {}
    for (idx, share_val), attr in zip(shares, attrs_ordered):
        owner = aa_owner_map.get(attr, None)
        share_map[attr] = {
            "owner": owner,
            "index": idx,
            "share_hex": hex(share_val)
        }

    # 5) Build CT JSON
    ct = {
        "meta": {
            "curve": "secp256r1",
            "n_attrs": len(attrs_ordered),
            "threshold": threshold,
            "attributes_ordered": attrs_ordered
        },
        "P_bytes_b64": base64.b64encode(P_bytes).decode(),
        "aes": aes,
        "shares": share_map
    }

    Path(out_ct_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_ct_path, "w") as f:
        json.dump(ct, f, indent=2)
    return out_ct_path
