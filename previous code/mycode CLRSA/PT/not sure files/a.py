# pseudonym_specific_key_signature_verification.py

import json
from Crypto.Hash import SHA256
from bplib.bp import BpGroup, G1Elem, G2Elem, Bn

# —————————————————————————————————————————————————————————
# Helper: hash an arbitrary string into G2, same as in your BlindIBS_scheme
# —————————————————————————————————————————————————————————
def hash_to_g2(data: str, group: BpGroup, g2: G2Elem) -> G2Elem:
    h = SHA256.new(data.encode("utf-8")).digest()
    order = group.order()
    bn = Bn.from_binary(h) % order
    return g2 * bn

# —————————————————————————————————————————————————————————
# 1) Load pseudonym identity & private key (a G2 element)
# —————————————————————————————————————————————————————————
with open("/home/nmuslim162022/Desktop/mycode/PT/pseudonym_private_key.json") as f:
    key_data = json.load(f)

pseudonym_identity = key_data["pseudonym_identity"]
sk_I_bytes         = bytes.fromhex(key_data["sk_I"])

# —————————————————————————————————————————————————————————
# 2) Load issuer public key α_g1
# —————————————————————————————————————————————————————————
with open("/home/nmuslim162022/Desktop/mycode/PT/issuer_pub.json") as f:
    pub = json.load(f)

alpha_g1_bytes = bytes.fromhex(pub["alpha_g1"])

# —————————————————————————————————————————————————————————
# 3) Setup pairing group & generators
# —————————————————————————————————————————————————————————
group = BpGroup()
g1    = group.gen1()
g2    = group.gen2()
order = group.order()

# Deserialize keys
sk_I    = G2Elem.from_bytes(sk_I_bytes,     group)  # your pseudonym-specific secret
alpha_g1 = G1Elem.from_bytes(alpha_g1_bytes, group)  # issuer’s public key

# —————————————————————————————————————————————————————————
# 4) Blind-IBS Signing + Verification
# —————————————————————————————————————————————————————————
def sign(sk_I: G2Elem, message: str):
    """Blind IBS sign under G2 key sk_I."""
    s   = order.random()
    H_m = hash_to_g2(message, group, g2)
    sigma1 = g1 * s                # G1Elem
    sigma2 = sk_I + (H_m * s)      # G2Elem
    return sigma1, sigma2

def verify(alpha_g1: G1Elem, identity: str, message: str, sigma1, sigma2):
    """Blind IBS verify: e(σ1, H_m)·e(α_g1, h_I) == e(g1, σ2)."""
    h_I  = hash_to_g2(identity, group, g2)
    H_m  = hash_to_g2(message,  group, g2)
    lhs  = group.pair(sigma1, H_m) * group.pair(alpha_g1, h_I)
    rhs  = group.pair(g1,      sigma2)
    return lhs == rhs

# —————————————————————————————————————————————————————————
# 5) Demo: sign & verify a message
# —————————————————————————————————————————————————————————
message = "confidential prescription threshold check"

sigma1, sigma2 = sign(sk_I, message)
print("Signature:")
print(" σ₁ (hex):", sigma1.export().hex())
print(" σ₂ (hex):", sigma2.export().hex())

valid = verify(alpha_g1, pseudonym_identity, message, sigma1, sigma2)
print("\nSignature valid?", "YES ✅" if valid else "NO ❌")
