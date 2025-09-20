# pseudonym_specific_key.py

import json
from Crypto.Hash import SHA256
from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.bn import Bn
from petlib.pack import encode, decode
import hashlib
from datetime import date
import time
import numpy as np
from typing import Dict, List, Any
import os

# File paths
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/pseudonym specific private key/crypto_parameters.json"
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/pseudonym specific private key//patient_credential_signature.json"

# Define the fixed attribute order (must match the server)
# ---- Global params / order ----
patient_credential_attribute_order = [
    'credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc'
]

# Initialize pairing group
group = BpGroup()
p = group.order()

# 1) Setup pairing group
group = BpGroup()
g1    = group.gen1()
g2    = group.gen2()
order = group.order()

# 2) Master key (PKG)
alpha    = order.random()   # Master secret
alpha_g1 = g1 * alpha       # For verification
alpha_g2 = g2 * alpha       # For unblinding

# 3) Hash‐to‐G2
def hash_to_g2(data: str):
    h = SHA256.new(data.encode()).digest()
    bn = Bn.from_binary(h) % order
    return g2 * bn

# 4) Blind‐IBS extraction
def user_blind_identity(identity: str):
    h_I       = hash_to_g2(identity)
    r         = order.random()
    h_I_blind = h_I + (g2 * r)
    return h_I, h_I_blind, r

def issuer_blind_key_extract(h_I_blind):
    return h_I_blind * alpha

def user_unblind(sk_I_blind, r):
    return sk_I_blind - (alpha_g2 * r)




def read_json_file(file_path):
    """
    Reads a JSON file from the given file path and returns the parsed JSON object.
    """
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        # #print(f"Error: File not found at {file_path}")
        return None
    except json.JSONDecodeError:
        # #print(f"Error: Failed to parse JSON file at {file_path}")
        return None

# --- Commitment ---
def compute_aggregate_commitment(H, attributes):
    """Compute the aggregate commitment for a set of attributes."""
    commitment = group.gen1()  # Start with neutral element
    for i, attr_value in enumerate(attributes):
        commitment = commitment.add(H[i].mul(attr_value))
    return commitment


def credential_commitment_func(pk_user, aggregate_commitment):
    """Compute the credential commitment."""
    return pk_user.add(aggregate_commitment)


def verify_signature(signature, pk_issuer, credential_commitment, g2):
    """Verify the signature using pairing operations."""
    return group.pair(signature, g2) == group.pair(credential_commitment, pk_issuer)



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






############################
############################
############################


# 5) Load patient pseudonym & run extraction
pp_file = "/home/nmuslim162022/Desktop/mycode2/pseudonym specific private key/patient_pseudonym_data.json"
out_file= "/home/nmuslim162022/Desktop/mycode2/pseudonym specific private key/pseudonym_private_key.json"

with open(pp_file) as f:
    pp = json.load(f)



iterations = 12
execution_times = []

for i in range(iterations):

    # Record the start time in nanoseconds
    start_time = time.perf_counter_ns()



    P_a = pp["P_patient_a"]
    P_b = pp["P_patient_b"]
    identity = f"{P_a}|{P_b}"

    h_I, h_I_blind, r = user_blind_identity(identity)

    sk_blind = issuer_blind_key_extract(h_I_blind)

    sk_I     = user_unblind(sk_blind, r)

    # Load patient credential, public parameters
    patient_credential = read_json_file(PATIENT_CREDENTIAL_FILE_PATH)
    parameters = read_json_file(PARAMETERS_FILE_PATH)
    signature = decode(bytes.fromhex(patient_credential['signature']))

    g1 = decode(bytes.fromhex(parameters['g1']))
    g2 = decode(bytes.fromhex(parameters['g2']))
    H = [decode(bytes.fromhex(h)) for h in parameters['H']]
    sk_issuer = Bn.from_hex(parameters['sk_issuer'])
    pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
    sk_user = Bn.from_hex(parameters['sk_user'])
    pk_user = decode(bytes.fromhex(parameters['pk_user']))

    # #print("g1: ", g1)
    # #print("g2: ", g2)
    # #print("H: ", H)
    # #print("sk_issuer: ", sk_issuer)
    # #print("pk_issuer: ", pk_issuer)
    # #print("pk_user: ", pk_user)


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







    # computation by the APC
    ### APC verifies the proof of knowledge of patient id from the patient credential
    ###############################################

    # Verify
    validity = zk_verify_hidden_attributes(
            g1, g2, H,
            pk_issuer, pk_user,
            proof
        )
    #print(f"\nVerification result: {validity}")


    
    #print ("zk_valid: ", zk_valid)

    # 6) Serialize everything
    result = {
        "pseudonym_identity": identity,
        "sk_I":               sk_I.export().hex(),
        "alpha_g1":           alpha_g1.export().hex(),
        "alpha_g2":           alpha_g2.export().hex()
    }

    '''
    with open(out_file, "w") as f:
        json.dump(result, f, indent=4)

    print("Saved pseudonym_private_key.json with sk_I, alpha_g1, alpha_g2")
    '''

    # Record the end time in nanoseconds
    end_time = time.perf_counter_ns()

    # Calculate the execution time in milliseconds
    execution_time_ms = (end_time - start_time) / 1_000_000
    #print(f"Execution time: {execution_time_ms} milliseconds")

    execution_times.append(execution_time_ms)

    #time.sleep(5)  # Sleep for 5 seconds before the next


# Remove outliers and calculate stats
trimmed_times = execution_times[1:-1]
if trimmed_times:
    avg_time = np.mean(trimmed_times)
    std_dev = np.std(trimmed_times)
    print("Execution Times:", execution_times)
    print("Trimmed Execution Times:", trimmed_times)
    print(f"Average Execution Time: {avg_time:.2f} ms")
    print(f"Standard Deviation: {std_dev:.2f} ms")   
    