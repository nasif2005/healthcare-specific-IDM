from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.pack import encode, decode
from petlib.bn import Bn
import json
import hashlib
import time
from typing import Dict, List, Any
import os
import numpy as np  # optional; used if you later re-enable timing stats

# -------------------- File paths --------------------
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/PT/crypto_parameters.json"
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/PT/patient_credential_signature.json"
PSEUDONYM_DATA_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/PT/patient_pseudonym_data.json"
SIGNED_TOKEN_OUT_PATH = "/home/nmuslim162022/Desktop/mycode2/signed_pseudonym_token.json"

# -------------------- Attribute order (must match issuer) --------------------
patient_credential_attribute_order = [
    'credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc'
]

# -------------------- Pairing group init --------------------
group = BpGroup()
g1 = group.gen1()
g2 = group.gen2()
order = group.order()
z = group.pair(g1, g2)

# -------------------- Example Schnorr params (toy, replace in production) --------------------
# Finite field params for the toy Schnorr signature over integers mod p1
p1 = 162259276829213363391578010288127  # large prime
q1 = 81129638414606681695789005144063   # divisor of p1-1
g1_schnorr = 2                           # generator of subgroup of order q1

# Schnorr signing key (example)
x_sign = 563452374
Y_sign = pow(g1_schnorr, x_sign, p1)     # public key

# ======================================================================
# Utilities
# ======================================================================

def read_json_file(file_path: str):
    """Load JSON from disk, return None on error."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

def group_element_to_hex(element):
    """Serialize a (petlib) group element to hex."""
    return encode(element).hex()

def hex_to_group_element(hex_str: str):
    """Deserialize a (petlib) group element from hex."""
    return decode(bytes.fromhex(hex_str))

def _sha256_to_scalar(s: str, mod: Bn) -> Bn:
    h = hashlib.sha256(s.encode("utf-8")).digest()
    return Bn.from_binary(h).mod(mod)

def _hash_challenge_to_scalar(parts: List[Any], mod: Bn) -> Bn:
    sha = hashlib.sha256()
    for obj in parts:
        if hasattr(obj, "export"):           # group elements (petlib)
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

# ======================================================================
# Commitment helpers (match issuers behavior)
# ======================================================================

def compute_aggregate_commitment(H, attributes):
    """Compute � m_i * H_i ; starts from gen1() per your issuer-side init quirk."""
    commitment = group.gen1()  # matches your APC init bug (+g1)
    for i, attr_value in enumerate(attributes):
        commitment = commitment.add(H[i].mul(attr_value))
    return commitment

def credential_commitment_func(pk_user, aggregate_commitment):
    """C = pk_user + � m_i H_i (and APC implicitly had +g1 in its init)."""
    return pk_user.add(aggregate_commitment)

def verify_signature(signature, pk_issuer, credential_commitment, g2):
    """Pairing check e(�, g2) == e(C, pk_issuer)."""
    return group.pair(signature, g2) == group.pair(credential_commitment, pk_issuer)

# ======================================================================
# ZK proof for hidden attributes (credential possession with disclosures)
# ======================================================================

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
    Does NOT include user's secret key (pk_user already commits it).
    """
    sigma = decode(bytes.fromhex(sigma_hex))  # G1 signature

    # Reconstruct the attribute map as signed by issuer
    info = patient_credential["info"]
    all_attrs_values: Dict[str, str] = {
        'credential_id':  info['credential_id'],
        'did_patient':    info['did_patient'],
        'patient_id':     info['patient_id'],
        'biometric_data': info['biometric_data'],
        'issue_date':     info['issue_date'],
        'did_apc':        info['did_apc'],
    }

    # Partition indices (hidden vs disclosed)
    hidden_idx, m_values = [], []
    for i, name in enumerate(patient_credential_attribute_order):
        m_i = _sha256_to_scalar(str(all_attrs_values[name]), order)
        m_values.append(m_i)
        if name not in disclosed_attribute_set:
            hidden_idx.append(i)

    # 1) Randomize signature
    r_rand = Bn.random(order)
    sigma_prime = sigma.add(g1.mul(r_rand))

    # 2) Blinding factors
    r_tilde = Bn.random(order)
    m_tilde = {i: Bn.random(order) for i in hidden_idx}

    # 3) H_hidden = �_{ihidden} (m_i * H_i)
    if hidden_idx:
        H_tilde_hidden = None
        for i in hidden_idx:
            t = H[i].mul(m_tilde[i])
            H_tilde_hidden = t if H_tilde_hidden is None else H_tilde_hidden.add(t)
    else:
        H_tilde_hidden = g1.mul(0)

    # 4) A = e(r�g1, g2) � e(H_hidden, pk_issuer)
    e1 = group.pair(g1.mul(r_tilde), g2)
    e2 = group.pair(H_tilde_hidden, pk_issuer)
    try:
        A = e1.mul(e2)
    except Exception:
        A = e1 * e2

    # 5) c = H(�2 || A || nonce)
    c = _hash_challenge_to_scalar([sigma_prime, A, nonce], order)

    # 6) Responses
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

def zk_verify_hidden_attributes(
    g1, g2, H,
    pk_issuer, pk_user,
    proof: Dict[str, Any]
) -> bool:
    """
    Verify proof: Term_Sig^{-c} � e(r�g1,g2) � e( � m_i H_i , pk_issuer ),
    with H_public including +g1 to match APCs aggregate init.
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

    # H_m_disclosed = � m_i H_i over disclosed
    if disclosed_idx:
        H_m_disclosed = None
        for i in disclosed_idx:
            m_i = _sha256_to_scalar(str(disclosed_vals[i]), order)
            t = H[i].mul(m_i)
            H_m_disclosed = t if H_m_disclosed is None else H_m_disclosed.add(t)
    else:
        H_m_disclosed = g1.mul(0)

    # H_public = pk_user + � disclosed + g1 (to match APC init)
    H_public = pk_user.add(H_m_disclosed).add(g1)

    # � m_i H_i for hidden
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

    # Term_Sig^{-c} = e(�2, g2)^{-c} � e(H_public, pk_issuer)^{c}
    c_mod = c.mod(order)
    neg_c = (order - c_mod).mod(order)
    e_sig_negc = group.pair(sigma_prime.mul(neg_c), g2)
    e_pub_posc = group.pair(H_public.mul(c_mod), pk_issuer)
    try:
        term_sig_pow = e_sig_negc.mul(e_pub_posc)
    except Exception:
        term_sig_pow = e_sig_negc * e_pub_posc

    # A2 = Term_Sig^{-c} � e(r�g1, g2) � e( � m_i H_i, pk_issuer )
    e_rand   = group.pair(g1.mul(rhat), g2)
    e_hidden = group.pair(H_mhat_hidden, pk_issuer)
    try:
        A_prime = term_sig_pow.mul(e_rand).mul(e_hidden)
    except Exception:
        A_prime = (term_sig_pow * e_rand) * e_hidden

    # Recompute c2
    c_prime = _hash_challenge_to_scalar([sigma_prime, A_prime, nonce], order)
    return c_prime == c

# ======================================================================
# NIZK binding proof (pseudonym � PatientID binding)
# ======================================================================

def generate_binding_proof(P_patient_a, P_patient_b, r, pk_patient, patient_id_str):
    """
    NIZK: prove that P_patient_a / z^{Hash(PatientID)} == z^{r}  (in GT)
          and     P_patient_b == pk_patient * r                 (in G2)
    """
    # 1. randomizers
    t1 = group.order().random()
    t2 = group.order().random()

    # 2. commitments
    T1 = z ** t1              # in GT
    T2 = pk_patient * t2      # in G2

    # 3. challenge
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()

    hasher = hashlib.sha256()
    hasher.update(encode(P_patient_a))
    hasher.update(encode(P_patient_b))
    hasher.update(encode(T1))
    hasher.update(encode(T2))
    hasher.update(encode(pk_patient))
    hasher.update(encode(patient_id_fr))
    c = Bn.from_hex(hasher.hexdigest()) % group.order()

    # 4. responses
    s1 = (t1 + c * r) % group.order()
    s2 = (t2 + c * r) % group.order()

    # 5. proof
    return {
        "T1": group_element_to_hex(T1),
        "T2": group_element_to_hex(T2),
        "c": c.hex(),
        "s1": s1.hex(),
        "s2": s2.hex()
    }

def verify_binding_proof(proof, P_patient_a, P_patient_b, pk_patient, patient_id_str):
    """Verify the NIZK binding proof."""
    T1 = hex_to_group_element(proof['T1'])
    T2 = hex_to_group_element(proof['T2'])
    c  = Bn.from_hex(proof['c'])
    s1 = Bn.from_hex(proof['s1'])
    s2 = Bn.from_hex(proof['s2'])

    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()

    # Eqn 1 (in GT): z^{s1} == T1 * ( (P_a / z^{pid_fr})^{c} )
    lhs1 = z ** s1
    patient_id_gt = z ** patient_id_fr
    p1_div_hash = P_patient_a * (patient_id_gt ** -1)
    rhs1 = T1 * (p1_div_hash ** c)
    check1 = (lhs1 == rhs1)

    # Eqn 2 (in G2, additive): pk_patient * s2 == T2 + (P_b * c)
    lhs2 = pk_patient * s2
    rhs2 = T2 + (P_patient_b * c)
    check2 = (lhs2 == rhs2)

    return check1 and check2

# ======================================================================
# Toy Schnorr signature over bytes (separate from pairings)
# ======================================================================

def schnorr_signature_generate(pseudonym_token_bytes: bytes, x_sign: int):
    """Generate Schnorr signature (s, c) on byte-string token."""
    r = 123456789  # fixed nonce for reproducibility in tests; use random in prod
    R = pow(g1_schnorr, r, p1)

    h = hashlib.sha256()
    h.update(R.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c = int.from_bytes(h.digest(), 'big') % q1

    s = (r - c * x_sign) % q1
    return s, c

def schnorr_signature_verify(pseudonym_token_bytes: bytes, s: int, c: int, Y_sign: int) -> bool:
    """Verify Schnorr signature (s, c) with public key Y_sign."""
    R_prime = (pow(g1_schnorr, s, p1) * pow(Y_sign, c, p1)) % p1

    h = hashlib.sha256()
    h.update(R_prime.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c_prime = int.from_bytes(h.digest(), 'big') % q1

    return c_prime == c

# ======================================================================
# Main
# ======================================================================

if __name__ == "__main__":
    iterations = 12
    execution_times = []

    for _ in range(iterations):
        start_time = time.perf_counter_ns()

        # 1) Load patient credential and public parameters
        patient_credential = read_json_file(PATIENT_CREDENTIAL_FILE_PATH)
        parameters = read_json_file(PARAMETERS_FILE_PATH)
        if patient_credential is None or parameters is None:
            raise RuntimeError("Missing input JSON files for credential / parameters.")

        signature = decode(bytes.fromhex(patient_credential['signature']))
        g1 = decode(bytes.fromhex(parameters['g1']))
        g2 = decode(bytes.fromhex(parameters['g2']))
        H = [decode(bytes.fromhex(h)) for h in parameters['H']]
        pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
        pk_user = decode(bytes.fromhex(parameters['pk_user']))
        # sk_issuer / sk_user loaded in params if needed elsewhere:
        # sk_issuer = Bn.from_hex(parameters['sk_issuer'])
        # sk_user   = Bn.from_hex(parameters['sk_user'])

        # 2) Hash attributes to scalars in the fixed order
        attribute_values = []
        for attr in patient_credential_attribute_order:
            value = patient_credential['info'][attr]
            attr_hash = hashlib.sha256(value.encode()).digest()
            attr_bn = Bn.from_binary(attr_hash).mod(order)
            attribute_values.append(attr_bn)

        # 3) Commitment and signature verification
        aggregate_commitment = compute_aggregate_commitment(H, attribute_values)
        credential_commitment = credential_commitment_func(pk_user, aggregate_commitment)

        try:
            signature_valid = verify_signature(signature, pk_issuer, credential_commitment, g2)
        except Exception as e:
            print("Signature verification threw:", e)
            signature_valid = False

        if not signature_valid:
            print("L Credential signature INVALID  aborting.")
            break

        # 4) Generate ZK proof revealing only patient_id
        patient_id_str = patient_credential['info']['patient_id']  # keep STRING
        disclosed_attribute_set = {"patient_id": patient_id_str}
        sigma_hex = patient_credential["signature"]
        nonce = os.urandom(16).hex()

        proof = zk_proof_generation_hidden_attributes(
            g1, g2, H,
            pk_issuer, pk_user,
            sigma_hex,
            patient_credential,
            disclosed_attribute_set,
            nonce
        )

        # 5) Load pseudonym bundle (PTA side)
        pseudonym_data = read_json_file(PSEUDONYM_DATA_FILE_PATH)
        if pseudonym_data is None:
            raise RuntimeError("Missing pseudonym data file.")

        P_patient_a = hex_to_group_element(pseudonym_data['P_patient_a'])
        P_patient_b = hex_to_group_element(pseudonym_data['P_patient_b'])
        rk_patient_to_HRR = hex_to_group_element(pseudonym_data['rk_patient_to_HRR'])
        encrypted_pid = bytes.fromhex(pseudonym_data['encrypted_pid'])

        # Correct secret 'r' and public key for the NIZK binding proof
        r_nizk = Bn.from_hex(pseudonym_data['r'])
        pk_patient_nizk = hex_to_group_element(pseudonym_data['pk_patient'])
        # ensure patient_id is STRING (fallback to patient_id_str if absent)
        patient_id_nizk = str(pseudonym_data.get('patient_id', patient_id_str))

        # 6) NIZK proof of binding (patient � PTA)
        binding_proof = generate_binding_proof(
            P_patient_a, P_patient_b, r_nizk, pk_patient_nizk, patient_id_nizk
        )

        # 7) PTA verifies binding proof
        is_valid = verify_binding_proof(
            binding_proof, P_patient_a, P_patient_b, pk_patient_nizk, patient_id_nizk
        )

        print("\n--- Final Result ---")
        if is_valid:
            print(" The NIZK binding proof is VALID.")
        else:
            print("L The NIZK binding proof is INVALID.")
            break

        # 8) Prepare pseudonym token bytes for Schnorr signing
        pseudonym_token_bytes = (
            bytes.fromhex(group_element_to_hex(P_patient_a)) +
            bytes.fromhex(group_element_to_hex(P_patient_b)) +
            bytes.fromhex(group_element_to_hex(rk_patient_to_HRR)) +
            encrypted_pid  # already bytes
        )

        # 9) Schnorr signature over the pseudonym token
        s, c = schnorr_signature_generate(pseudonym_token_bytes, x_sign)
        '''
        print("\nSignature generated:")
        print("s:", s)
        print("c:", c)
        print("Y_sign:", Y_sign)
        '''

        # 10) Save signed token (optional)
        data_to_store = {
            "info": {
                "P_patient_a": group_element_to_hex(P_patient_a),
                "P_patient_b": group_element_to_hex(P_patient_b),
                "rk_patient_to_HRR": group_element_to_hex(rk_patient_to_HRR),
                "encrypted_pid": encrypted_pid.hex()
            },
            "signature": {
                "c": c,
                "s": s,
                "Y_sign": Y_sign
            }
        }
        with open(SIGNED_TOKEN_OUT_PATH, "w") as f:
            json.dump(data_to_store, f, indent=2)

        # 11) Verify Schnorr signature (self-check)
        valid = schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign)
        print("\nSignature valid:", valid)

        # timing
        end_time = time.perf_counter_ns()
        execution_time_ms = (end_time - start_time) / 1_000_000
        execution_times.append(execution_time_ms)
        print(f"Execution time: {execution_time_ms:.2f} ms")

    # If you later want stats, uncomment:
    trimmed_times = execution_times[1:-1]
    if trimmed_times:
         avg_time = np.mean(trimmed_times)
         std_dev = np.std(trimmed_times)
         print("Execution Times:", execution_times)
         print("Trimmed Execution Times:", trimmed_times)
         print(f"Average Execution Time: {avg_time:.2f} ms")
         print(f"Standard Deviation: {std_dev:.2f} ms")
