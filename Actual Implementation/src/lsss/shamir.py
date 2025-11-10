# src/lsss/shamir.py
# Simple Shamir Secret Sharing over integers mod a large prime (ECC order)
import random
from ecpy.curves import Curve

curve = Curve.get_curve('secp256r1')
MOD = curve.order  # large prime modulus

def _eval_poly(coeffs, x):
    """Evaluate polynomial at x."""
    res = 0
    pow_x = 1
    for c in coeffs:
        res = (res + c * pow_x) % MOD
        pow_x = (pow_x * x) % MOD
    return res

def split_secret(secret_int, n, t):
    """
    Split secret_int into n shares with threshold t.
    Returns list of (index, share_int).
    """
    if not (1 <= t <= n):
        raise ValueError("Threshold t must be between 1 and n.")
    coeffs = [secret_int] + [random.randrange(1, MOD) for _ in range(t-1)]
    shares = [(i, _eval_poly(coeffs, i)) for i in range(1, n+1)]
    return shares

def _inv(x):
    return pow(x, -1, MOD)

def reconstruct_secret(points):
    """
    Given list of (x, y) shares, reconstruct the secret (constant term).
    """
    x_vals = [x for x, _ in points]
    y_vals = [y for _, y in points]
    k = len(points)
    secret = 0
    for j in range(k):
        xj, yj = x_vals[j], y_vals[j]
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            xm = x_vals[m]
            num = (num * (-xm)) % MOD
            den = (den * (xj - xm)) % MOD
        lagrange_coeff = (num * _inv(den)) % MOD
        secret = (secret + yj * lagrange_coeff) % MOD
    return secret
