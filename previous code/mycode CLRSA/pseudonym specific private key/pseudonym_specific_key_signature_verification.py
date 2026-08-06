#!/usr/bin/env python3
# pseudonym_specific_key_signature_verification.py

import json
from Crypto.Hash import SHA256
from bplib.bp import BpGroup, G1Elem, G2Elem, Bn

# —————————————————————————————————————————————————————————————————
# 1) Load pseudonym key, identity, and issuer public keys from JSON
# —————————————————————————————————————————————————————————————————
with open("/home/nmuslim162022/Desktop/mycode/PT/pseudonym_private_key.json") as f:
    data = json.load(f)

identity    = data["pseudonym_identity"]
sk_I_hex    = data["sk_I"]
alpha_g1_hex= data["alpha_g1"]
alpha_g2_hex= data["alpha_g2"]

# —————————————————————————————————————————————————————————————————
# 2) Initialize pairing group & generators (BN254)
# —————————————————————————————————————————————————————————————————
group = BpGroup()
g1    = group.gen1()
g2    = group.gen2()
order = group.order()

# —————————————————————————————————————————————————————————————————
# 3) Deserialize: 
#    - sk_I ∈ G2 
#    - α_g1 ∈ G1 
#    - α_g2 ∈ G2 (if you ever need it)
# —————————————————————————————————————————————————————————————————
sk_I     = G2Elem.from_bytes(bytes.fromhex(sk_I_hex),     group)
alpha_g1 = G1Elem.from_bytes(bytes.fromhex(alpha_g1_hex), group)
alpha_g2 = G2Elem.from_bytes(bytes.fromhex(alpha_g2_hex), group)

# —————————————————————————————————————————————————————————————————
# 4) Hash‐to‐G2 helper (must match extraction code)
# —————————————————————————————————————————————————————————————————
def hash_to_g2(msg: str) -> G2Elem:
    h = SHA256.new(msg.encode("utf-8")).digest()
    bn = Bn.from_binary(h) % order
    return g2 * bn

# —————————————————————————————————————————————————————————————————
# 5) Blind‐IBS sign / verify
# —————————————————————————————————————————————————————————————————
def sign(sk: G2Elem, msg: str):
    s    = order.random()
    H_m  = hash_to_g2(msg)
    sigma1 = g1 * s
    sigma2 = sk + (H_m * s)
    return sigma1, sigma2

def verify(identity: str, msg: str, sigma1, sigma2) -> bool:
    h_I  = hash_to_g2(identity)
    H_m  = hash_to_g2(msg)
    lhs  = group.pair(sigma1, H_m) * group.pair(alpha_g1, h_I)
    rhs  = group.pair(g1,      sigma2)
    return lhs == rhs

# —————————————————————————————————————————————————————————————————
# 6) Demo: sign and verify a message under the pseudonym-specific key
# —————————————————————————————————————————————————————————————————
if __name__ == "__main__":
    message = "confidential prescription threshold check"

    sigma1, sigma2 = sign(sk_I, message)
    print("σ₁ (hex):", sigma1.export().hex())
    print("σ₂ (hex):", sigma2.export().hex())

    valid = verify(identity, message, sigma1, sigma2)
    print("\nSignature valid?", "YES ✅" if valid else "NO ❌")
