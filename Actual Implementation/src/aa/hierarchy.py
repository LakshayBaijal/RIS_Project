# src/aa/hierarchy.py
"""
Implements a RootAuthority that can delegate secrets to SubAuthorities.
Each SubAuthority (SA) derives its secret base from the RA master secret.
"""

import os
from dataclasses import dataclass
from typing import Dict, List

from ecpy.curves import Curve, Point
from src.crypto.ecc import scalar_mul, point_add, point_to_bytes, hash_to_int, n, curve

@dataclass
class RootPublicParams:
    curve_name: str
    P_root_bytes: bytes
    sub_authorities: Dict[str, bytes]  # SA name -> public key bytes

class SubAuthority:
    def __init__(self, name: str, ra_secret_component: int, attributes: List[str]):
        """
        Each SubAuthority has a derived master secret:
            alpha_SA = H(name) + ra_secret_component  (mod n)
        It manages its own attributes with per-attribute keys.
        """
        self.name = name
        self.attributes = attributes
        self.alpha_SA = (hash_to_int(name.encode()) + ra_secret_component) % n
        self.k_attr = {attr: int.from_bytes(os.urandom(32), 'big') % n for attr in attributes}
        self.P_pub = scalar_mul(self.alpha_SA)
        self.PK_attrs = {attr: scalar_mul(k) for attr, k in self.k_attr.items()}

    def describe(self):
        return {
            "name": self.name,
            "P_pub_hex": point_to_bytes(self.P_pub).hex()[:40],
            "attributes": list(self.attributes)
        }

class RootAuthority:
    def __init__(self, name="RootAuthority"):
        self.name = name
        self.alpha_RA = int.from_bytes(os.urandom(32), 'big') % n
        self.P_root = scalar_mul(self.alpha_RA)
        self.sub_authorities: Dict[str, SubAuthority] = {}

    def delegate_sub_authority(self, sa_name: str, attributes: List[str]):
        """
        RA creates a SubAuthority derived from its master secret.
        """
        sa = SubAuthority(sa_name, self.alpha_RA, attributes)
        self.sub_authorities[sa_name] = sa
        return sa

    def get_public_params(self) -> RootPublicParams:
        sa_dict = {sa.name: point_to_bytes(sa.P_pub) for sa in self.sub_authorities.values()}
        return RootPublicParams(curve.name, point_to_bytes(self.P_root), sa_dict)

    def describe_hierarchy(self):
        data = {"RootAuthority": self.name, "Root_P_hex": point_to_bytes(self.P_root).hex()[:40]}
        data["SubAuthorities"] = {sa.name: sa.describe() for sa in self.sub_authorities.values()}
        return data
