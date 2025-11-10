# src/aa/authority.py
# Simple Multi-Authority (AA) setup and KeyGen for demo purposes.
# Each Authority holds:
#   - master secret alpha (scalar)
#   - per-attribute secret k_attr (scalar) for each attribute it manages
# Public params:
#   - P_pub = alpha * G
#   - PK_attr = k_attr * G  (published)
#
# KeyGen for a user UID and attribute attr returns SK_scalar and SK_point:
#   SK_scalar = alpha + H(UID) * k_attr  (mod n)
#   SK_point  = SK_scalar * G
#
# This binds attribute key to UID via hash H(UID).

from dataclasses import dataclass
import os
from typing import Dict
from hashlib import sha256

from ecpy.curves import Curve, Point

from src.crypto.ecc import scalar_mul, point_to_bytes, hash_to_int, G, n, curve

@dataclass
class AuthorityPublicParams:
    curve_name: str
    P_pub_point: Point
    PK_attrs: Dict[str, bytes]  # attr -> serialized point bytes

class Authority:
    def __init__(self, name: str, attributes: list):
        """
        name: identifier for this authority
        attributes: list of attribute names this AA controls
        """
        self.name = name
        self.attributes = list(attributes)
        # master secret scalar alpha (random)
        self.alpha = int.from_bytes(os.urandom(32), 'big') % n
        # per-attribute secret scalars k_attr
        self.k_attr = {attr: int.from_bytes(os.urandom(32), 'big') % n for attr in self.attributes}

        # public params
        self.P_pub = scalar_mul(self.alpha)   # alpha * G
        self.PK_attrs = {attr: scalar_mul(self.k_attr[attr]) for attr in self.attributes}

    def get_public_params(self) -> AuthorityPublicParams:
        pk_serialized = {attr: point_to_bytes(self.PK_attrs[attr]) for attr in self.attributes}
        return AuthorityPublicParams(
            curve_name=curve.name,
            P_pub_point=self.P_pub,
            PK_attrs=pk_serialized
        )

    def keygen_for_user(self, uid: str, attr: str):
        """
        Issue a user-secret for (uid, attr).
        Returns a dict with SK_scalar and SK_point (serialized).
        Formula (toy/demo): SK = alpha + H(uid) * k_attr  (mod n)
        """
        if attr not in self.attributes:
            raise ValueError(f"Attribute {attr} not managed by authority {self.name}")

        # hash UID to integer mod n
        h = hash_to_int(uid.encode())
        sk_scalar = (self.alpha + (h * self.k_attr[attr]) ) % n
        sk_point = scalar_mul(sk_scalar)
        return {
            "uid": uid,
            "authority": self.name,
            "attribute": attr,
            "sk_scalar": sk_scalar,
            "sk_point_bytes": point_to_bytes(sk_point)
        }
