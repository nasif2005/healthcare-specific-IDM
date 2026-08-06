# zk_hidden_presentation.py
# Single-file implementation:
#   - ZK Proof Generation for Hidden Attributes (no sk_user masking)
#   - ZK Proof Verification for Hidden Attributes
#   - main() demo (prove + verify with patient_id disclosed)

from bplib.bp import BpGroup
from petlib.pack import encode, decode
from petlib.bn import Bn
import hashlib
from typing import Dict, List, Any
import json
import os

# ---- Global params / order ----
patient_credential_attribute_order = [
    'credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc'
]

group = BpGroup()
order = group.order()

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON file at {file_path}")
        return None

# -------------------- Utilities --------------------

def _sha256_to_scalar(s: str, mod: Bn) -> Bn:
    h = hashlib.sha256(s.encode("utf-8")).digest()
    return Bn.from_binary(h).mod(mod)

def _hash_challenge_to_scalar(parts: List[Any], mod: Bn) -> Bn:
    sha = hashlib.sha256()
    for obj in parts:
        if hasattr(obj, "export"):    # group elements
            sha.update(encode(obj))
        elif isinstance(obj, (bytes, bytearray)):
            sha.update(obj)
        elif isinstance(obj, str):
            sha.update(obj.encode("utf-8"))
        elif isinstance(obj, int):
            sha.update(obj.to_bytes((obj.bit_length() + 7)//8 or 1, "big"))
        elif isinstance(obj, Bn):
            sha.update(obj.hex().encode("utf-8"))
        else:
            sha.update(str(obj).encode("utf-8"))
    return Bn.from_binary(sha.digest()).mod(mod)

# -------------------- Prover --------------------

def zk_proof_generation_hidden_attributes(
    g1, g2, H,
    pk_issuer, pk_user,
    sigma_hex: str,
    patient_credential: Dict[str, Any],
    disclosed_attribute_set: Dict[str, str],
    nonce: str
) -> Dict[str, Any]:
    """
    Build ZK proof revealing disclosed_attribute_set; hide the rest.
    Does NOT mask sk_user (pk_user already commits it).
    """
    sigma = decode(bytes.fromhex(sigma_hex))  # G1 signature

    # Build attribute map exactly as issuer signed (hash of strings)
    info = patient_credential["info"]
    all_attrs_values: Dict[str, str] = {
        'credential_id':  info['credential_id'],
        'did_patient':    info['did_patient'],
        'patient_id':     info['patient_id'],
        'biometric_data': info['biometric_data'],
        'issue_date':     info['issue_date'],
        'did_apc':        info['did_apc'],
    }

    # Partition indices
    hidden_idx, m_values = [], []
    for i, name in enumerate(patient_credential_attribute_order):
        m_i = _sha256_to_scalar(str(all_attrs_values[name]), order)
        m_values.append(m_i)
        if name not in disclosed_attribute_set:
            hidden_idx.append(i)

    # 1) Randomize signature
    r_rand = Bn.random(order)
    sigma_prime = sigma.add(g1.mul(r_rand))

    # 2) Blinding factors (no sk term)
    r_tilde = Bn.random(order)
    m_tilde = {i: Bn.random(order) for i in hidden_idx}

    # 3) H̃_hidden = sum_{i∈hidden} m̃_i H_i
    if hidden_idx:
        H_tilde_hidden = None
        for i in hidden_idx:
            t = H[i].mul(m_tilde[i])
            H_tilde_hidden = t if H_tilde_hidden is None else H_tilde_hidden.add(t)
    else:
        H_tilde_hidden = g1.mul(0)

    # 4) A = e(r̃·g1, g2) · e(H̃_hidden, pk_issuer)
    e1 = group.pair(g1.mul(r_tilde), g2)
    e2 = group.pair(H_tilde_hidden, pk_issuer)
    try:
        A = e1.mul(e2)
    except Exception:
        A = e1 * e2

    # 5) c = H(σ′ || A || nonce)
    c = _hash_challenge_to_scalar([sigma_prime, A, nonce], order)

    # 6) Responses (no sk̂)
    rhat = (r_tilde + c.mod_mul(r_rand, order)).mod(order)
    mhat = {i: (m_tilde[i] + c.mod_mul(m_values[i], order)).mod(order) for i in hidden_idx}

    return {
        "sigma_prime": encode(sigma_prime).hex(),
        "c": c.hex(),
        "rhat": rhat.hex(),
        "mhat": {str(i): mhat[i].hex() for i in hidden_idx},
        "disclosed": {k: all_attrs_values[k] for k in disclosed_attribute_set.keys()},
        "nonce": nonce,
    }

# -------------------- Verifier --------------------

def zk_verify_hidden_attributes(
    g1, g2, H,
    pk_issuer, pk_user,
    proof: Dict[str, Any]
) -> bool:
    """
    Verify proof: Term_Sig^{-c} · e(r̂·g1,g2) · e( Σ m̂_i H_i , pk_issuer ).
    Adjusted to match APC’s commitment init bug: aggregate started at gen1() (extra +g1).
    """
    try:
        sigma_prime = decode(bytes.fromhex(proof["sigma_prime"]))
        c           = Bn.from_hex(proof["c"])
        rhat        = Bn.from_hex(proof["rhat"])
        mhat        = {int(k): Bn.from_hex(v) for k, v in proof["mhat"].items()}
        disclosed   = proof["disclosed"]
        nonce       = proof["nonce"]
    except Exception:
        return False

    # Partition
    disclosed_idx, hidden_idx, disclosed_vals = [], [], {}
    for i, name in enumerate(patient_credential_attribute_order):
        if name in disclosed:
            disclosed_idx.append(i)
            disclosed_vals[i] = disclosed[name]
        else:
            hidden_idx.append(i)

    # H_public = pk_user + sum_{disclosed} m_i H_i + g1  (match APC's gen1() init)
    if disclosed_idx:
        H_m_disclosed = None
        for i in disclosed_idx:
            m_i = _sha256_to_scalar(str(disclosed_vals[i]), order)
            t = H[i].mul(m_i)
            H_m_disclosed = t if H_m_disclosed is None else H_m_disclosed.add(t)
    else:
        H_m_disclosed = g1.mul(0)

    H_public = pk_user.add(H_m_disclosed).add(g1)  # extra +g1 due to APC init

    # Σ m̂_i H_i
    if hidden_idx:
        H_mhat_hidden = None
        for i in hidden_idx:
            mhi = mhat.get(i)
            if mhi is None:
                return False
            t = H[i].mul(mhi)
            H_mhat_hidden = t if H_mhat_hidden is None else H_mhat_hidden.add(t)
    else:
        H_mhat_hidden = g1.mul(0)

    # Term_Sig^{-c} = e(σ′, g2)^{-c} · e(H_public, pk_issuer)^{c}
    c_mod = c.mod(order)
    neg_c = (order - c_mod).mod(order)
    e_sig_negc = group.pair(sigma_prime.mul(neg_c), g2)
    e_pub_posc = group.pair(H_public.mul(c_mod), pk_issuer)
    try:
        term_sig_pow = e_sig_negc.mul(e_pub_posc)
    except Exception:
        term_sig_pow = e_sig_negc * e_pub_posc

    # A′ = Term_Sig^{-c} · e(r̂·g1, g2) · e( Σ m̂_i H_i, pk_issuer )
    e_rand   = group.pair(g1.mul(rhat), g2)
    e_hidden = group.pair(H_mhat_hidden, pk_issuer)
    try:
        A_prime = term_sig_pow.mul(e_rand).mul(e_hidden)
    except Exception:
        A_prime = (term_sig_pow * e_rand) * e_hidden

    # c′
    c_prime = _hash_challenge_to_scalar([sigma_prime, A_prime, nonce], order)
    return c_prime == c

# -------------------- MAIN DEMO --------------------
if __name__ == "__main__":
    PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT/crypto_parameters.json"
    PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT/patient_credential_signature.json"

    pairing_parameter = read_json_file(PARAMETERS_FILE_PATH)
    if pairing_parameter is None:
        raise SystemExit(1)

    g1 = decode(bytes.fromhex(pairing_parameter["g1"]))
    g2 = decode(bytes.fromhex(pairing_parameter["g2"]))
    H  = [decode(bytes.fromhex(hx)) for hx in pairing_parameter["H"]]
    pk_issuer = decode(bytes.fromhex(pairing_parameter["pk_issuer"]))
    pk_user   = decode(bytes.fromhex(pairing_parameter["pk_user"]))

    patient_credential = read_json_file(PATIENT_CREDENTIAL_FILE_PATH)
    if patient_credential is None:
        raise SystemExit(1)

    # Disclose only patient_id
    disclosed_attribute_set = {"patient_id": patient_credential['info']['patient_id']}
    sigma_hex = patient_credential["signature"]
    nonce = os.urandom(16).hex()

    # Prove
    proof = zk_proof_generation_hidden_attributes(
        g1, g2, H,
        pk_issuer, pk_user,
        sigma_hex,
        patient_credential,
        disclosed_attribute_set,
        nonce
    )

    print("Generated proof (truncated):")
    preview = {k: (v if k not in ("mhat", "sigma_prime") else "[omitted]") for k, v in proof.items()}
    print(json.dumps(preview, indent=2))

    # Verify
    ok = zk_verify_hidden_attributes(
        g1, g2, H,
        pk_issuer, pk_user,
        proof
    )
    print(f"\nVerification result: {ok}")
