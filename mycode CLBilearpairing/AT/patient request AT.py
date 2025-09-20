# patient request AT.py
from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.pack import encode, decode
from petlib.bn import Bn
import json
import requests
import hashlib
import time
from datetime import date
import numpy as np
import secrets
from sympy import mod_inverse
from typing import Dict, List, Any
import os

# File paths
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT/crypto_parameters.json"
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT/patient_credential_signature.json"

# URL of the APC server
apc_url = 'http://127.0.0.1:4000/request_AT_credential_signature'

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


# --- Commitment ---
def compute_aggregate_commitment(H, attributes):
    """Compute the aggregate commitment for a set of attributes."""
    commitment = group.gen1()
    for i, attr_value in enumerate(attributes):
        commitment = commitment.add(H[i].mul(attr_value))
    return commitment


def credential_commitment_func(pk_user, aggregate_commitment):
    """Compute the credential commitment."""
    return pk_user.add(aggregate_commitment)


def verify_signature(signature, pk_issuer, credential_commitment, g2):
    """Verify the signature using pairing operations."""
    return group.pair(signature, g2) == group.pair(credential_commitment, pk_issuer)


# --- patient credential Zero-Knowledge Proof Generation ---

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


# --- patient credential Zero-Knowledge Proof Verification ---

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





# --- Public parameters for Appointment Token ---
p_AT = 23
q_AT = 11
g_AT = 2
h_AT = 3  # independent generator for Pedersen commitment

# APC keypair (private/public key)
x_APC = 7
Y_APC = 13

# --- Hash helpers ---
def H_to_q_bytes(*parts: bytes) -> int:
    h_ = hashlib.sha256()
    for part in parts:
        h_.update(part)
    return int.from_bytes(h_.digest(), "big") % q_AT

def int_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

def H_msg1_to_scalar(appointment_token_id: bytes) -> int:
    # Hash → Z_{q_AT} for the hidden attribute
    return H_to_q_bytes(appointment_token_id)

# --- Patient: Pedersen commit to hidden appointment_token_id ---
def pedersen_commit(appointment_token_id: bytes):
    m1 = H_msg1_to_scalar(appointment_token_id)
    t  = secrets.randbelow(q_AT - 1) + 1
    commit = (pow(g_AT, m1, p_AT) * pow(h_AT, t, p_AT)) % p_AT  # commit = g^m1 * h^t
    return m1, t, commit

# --- APC steps ---
def APC_send_R(x_APC: int):
    """APC generates ephemeral R = g^r and sends to the patient."""
    r = secrets.randbelow(q_AT - 1) + 1
    R = pow(g_AT, r, p_AT)
    return r, R

def APC_respond(r: int, x_APC: int, Y_APC: int, expiration_date: bytes, cu: int):
    """APC computes blinded response s' using c' = cu + cs."""
    cs = H_to_q_bytes(int_bytes(Y_APC), expiration_date)
    c_prime = (cu + cs) % q_AT
    s_prime = (r + c_prime * x_APC) % q_AT
    return s_prime, expiration_date

# --- Patient steps ---
def patient_start(Y_APC: int, R: int, appointment_token_id: bytes):
    """Patient blinds R and commits to appointment_token_id."""
    m1, t, commit = pedersen_commit(appointment_token_id)
    u = secrets.randbelow(q_AT - 1) + 1
    v = secrets.randbelow(q_AT - 1) + 1

    R_prime  = (R * pow(Y_APC, u, p_AT) * pow(g_AT, v, p_AT)) % p_AT
    cu_prime = H_to_q_bytes(int_bytes(R_prime), int_bytes(commit))  # cu' = Hash(R' || commit)
    cu       = (cu_prime + u) % q_AT                                # cu = cu' + u

    return {
        "u": u,
        "v": v,
        "t": t,
        "commit": commit,
        "R_prime": R_prime,
        "cu_prime": cu_prime,
        "cu": cu,
    }

def patient_finalize(Y_APC: int, expiration_date: bytes, transcript: dict, s_prime: int):
    """Patient unblinds the response to obtain (s, c)."""
    v        = transcript["v"]
    cu_prime = transcript["cu_prime"]

    s  = (s_prime + v) % q_AT
    cs = H_to_q_bytes(int_bytes(Y_APC), expiration_date)  # cs = Hash(Y_APC || expiration_date)
    c  = (cu_prime + cs) % q_AT
    return s, c, transcript["t"]

# --- Verification Appointment Token signature ---
def verify_appointment_token_signature(Y_APC: int, appointment_token_id: bytes, expiration_date: bytes,
           sig: tuple[int, int], t: int) -> bool:
    """Verifier checks that (s, c) is a valid partially blind signature."""
    s, c = sig

    # m1 and commit'
    m1 = H_msg1_to_scalar(appointment_token_id)
    commit_prime = (pow(g_AT, m1, p_AT) * pow(h_AT, t, p_AT)) % p_AT

    # cs' = Hash(Y_APC || expiration_date)
    cs_prime = H_to_q_bytes(int_bytes(Y_APC), expiration_date)

    # R'' = g^s · (Y_APC^c)^(-1)
    Y_c = pow(Y_APC, c, p_AT)
    inv_Y_c = mod_inverse(Y_c, p_AT)
    R_dd = (pow(g_AT, s, p_AT) * inv_Y_c) % p_AT

    # cu' = Hash(R'' || commit')
    cu_prime = H_to_q_bytes(int_bytes(R_dd), int_bytes(commit_prime))

    # accept iff c == cu' + cs' (mod q_AT)
    return c == (cu_prime + cs_prime) % q_AT



#############################
# Main Execution Block      #
#############################


num_iterations = 12
execution_times = []

for i in range(num_iterations):


    # Record the start time
    start_time = time.perf_counter_ns()



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





    appointment_token_id = "8ff59cf4-6224-4644-8c65-88d0143dded4".encode("utf-8")
    # APC -> Patient: R
    r, R = APC_send_R(x_APC)

    # Patient: compute R', cu', cu = cu' + u
    transcript = patient_start(Y_APC, R, appointment_token_id)
    cu = transcript["cu"]


    ### APC verifies the proof of knowledge of patient id from the patient credential
    ###############################################

    # Verify
    validity = zk_verify_hidden_attributes(
            g1, g2, H,
            pk_issuer, pk_user,
            proof
        )
    #print(f"\nVerification result: {validity}")





    expiration_date = "2025-07-17".encode("utf-8")

    # APC: s' using c' = cu + cs
    s_prime, expiration_date = APC_respond(r, x_APC, Y_APC, expiration_date, cu)

    # Patient: s = s' + v, c = cu' + cs
    s, c, t = patient_finalize(Y_APC, expiration_date, transcript, s_prime)


    # Verify Appointment Token signature
    validity = verify_appointment_token_signature(Y_APC, appointment_token_id, expiration_date, (s, c), t)
    #print("Partially Blind Schnorr signature valid:", validity)




    # Decode before JSON serialization
    appointment_token_id_str = appointment_token_id.decode("utf-8")
    expiration_date_str = expiration_date.decode("utf-8")

    appointment_token = {
                "info": {
                    "appointment_token_id": appointment_token_id_str,
                    "expiration_date": expiration_date_str
                },
                "signature": {
                    "c": str(c),
                    "s": str(s),
                    "t": str(t)
                }
            }

    #print ("appointment_token: " , appointment_token )


#with open("/home/nmuslim162022/Desktop/mycode2/AT/AT_credential_signature.json", 'w') as json_file:
#               json.dump(appointment_token, json_file, indent=4)



    end_time = time.perf_counter_ns()
    exec_time_ms = (end_time - start_time) / 1_000_000
    execution_times.append(exec_time_ms)


# Exclude first and last execution times (reduce noise)
trimmed_times = execution_times[1:-1]

if trimmed_times:
    avg_time = np.mean(trimmed_times)
    std_time = np.std(trimmed_times)
    print("Execution Times:", execution_times)
    print("Trimmed Execution Times:", trimmed_times)
    print(f"Average Execution Time: {avg_time:.2f} ms")
    print(f"Standard Deviation: {std_time:.2f} ms")
else:
    print("No valid execution times to calculate performance metrics.")