# src/user/user.py
# User-side logic: generate USK (user secret d) and compute TSKs from SKs issued by AAs.
import os
from typing import Dict, List
from ecpy.curves import Curve, Point

from src.crypto.ecc import scalar_mul, point_to_bytes, hash_to_int, n

curve = Curve.get_curve('secp256r1')

class User:
    def __init__(self, uid: str):
        self.uid = uid
        # USK = user's secret scalar d (kept private)
        self.d = int.from_bytes(os.urandom(32), 'big') % n

    def get_USK(self):
        """Return user secret scalar (should remain private)."""
        return self.d

    def compute_TSKs(self, sks: List[Dict]) -> List[Dict]:
        """
        Given a list of SKs (each dict contains 'attribute' and 'sk_scalar'),
        compute TSK = SK + d (mod n) for each and return list of TSK dicts.
        """
        tsk_list = []
        for sk in sks:
            attr = sk['attribute']
            sk_scalar = sk['sk_scalar'] % n
            tsk_scalar = (sk_scalar + self.d) % n
            tsk_point = scalar_mul(tsk_scalar)
            tsk_list.append({
                "uid": self.uid,
                "attribute": attr,
                "tsk_scalar": tsk_scalar,
                "tsk_point_bytes": point_to_bytes(tsk_point)
            })
        return tsk_list

    def recover_SKs_from_TSKs(self, tsk_list: List[Dict]) -> List[Dict]:
        """
        Given TSKs (as stored at EA), the user can subtract d to get SK:
           SK = TSK - d  (mod n)  where subtraction is scalar arithmetic
        Return list of recovered SK dicts.
        """
        recovered = []
        for tsk in tsk_list:
            attr = tsk['attribute']
            tsk_scalar = tsk['tsk_scalar'] % n
            sk_scalar = (tsk_scalar - self.d) % n
            sk_point = scalar_mul(sk_scalar)
            recovered.append({
                "attribute": attr,
                "sk_scalar": sk_scalar,
                "sk_point_bytes": point_to_bytes(sk_point)
            })
        return recovered
