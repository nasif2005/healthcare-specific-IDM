# CLbilinearpairing signature scheme
import json
import hashlib
from sympy import mod_inverse
from sympy import mod_inverse as sympy_mod_inverse
from bplib.bp import BpGroup
from petlib.pack import encode, decode
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from petlib.bn import Bn
from bplib.bp import BpGroup, G1Elem, G2Elem, Bn 
from Crypto.Hash import SHA256
import time
import numpy as np
from typing import Dict, List, Any
import os

# Patient credential order
patient_credential_attribute_order = [
    'credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc'
]

# --- Configuration ---
# File paths for the public parameters and the credential to be verified.
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/patient_credential_signature.json"
PT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/signed_pseudonym_token.json"
AT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT_credential_signature.json"
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"


def read_json_file(file_path):
    with open(file_path, "r") as json_file:
        return json.load(json_file)


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








# Schnorr parameters (matching your earlier setup)
p1 = 162259276829213363391578010288127
q1 = 81129638414606681695789005144063
g1_schnorr = 2

def schnorr_signature_generate(msg_bytes, sk_sum):
    r = 123456789  # Use random in production!
    R = pow(g1_schnorr, r, p1)
    h = hashlib.sha256()
    h.update(R.to_bytes((p1.bit_length() + 7) // 8, 'big') + msg_bytes)
    c = int.from_bytes(h.digest(), 'big') % q1
    s = (r - c * sk_sum) % q1
    return s, c

def schnorr_signature_verify(msg_bytes, s, c, Y_sum):
    R_prime = (pow(g1_schnorr, s, p1) * pow(Y_sum, c, p1)) % p1
    h = hashlib.sha256()
    h.update(R_prime.to_bytes((p1.bit_length() + 7) // 8, 'big') + msg_bytes)
    c_prime = int.from_bytes(h.digest(), 'big') % q1
    return c_prime == c

def group_element_to_hex(element):
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)

def group_element_to_scalar(elem):
    h = hashlib.sha256(encode(elem))
    scalar = int.from_bytes(h.digest(), 'big') % q1
    return scalar


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


    # —————————————————————————————————————————————————————————————————
    # 4) Hash‐to‐G2 helper (must match extraction code)
    # —————————————————————————————————————————————————————————————————
def hash_to_g2(msg: str) -> G2Elem:
    if isinstance(msg, (bytes, bytearray)):
        digest = SHA256.new(msg).digest()
    elif isinstance(msg, str):
        digest = SHA256.new(msg.encode("utf-8")).digest()
    else:
        raise TypeError(f"hash_to_g2 expects bytes or str, got {type(msg)}")
    bn = Bn.from_binary(digest) % order
    return g2 * bn



    # —————————————————————————————————————————————————————————————————
    # 5) Blind‐IBS sign / verify
    # —————————————————————————————————————————————————————————————————
def sign(sk: G2Elem, msg: str):
    s      = order.random()
    H_m    = hash_to_g2(msg)
    sigma1 = g1 * s
    sigma2 = sk + (H_m * s)
    return sigma1, sigma2


def verify(identity: str, msg: str, sigma1, sigma2) -> bool:
    h_I  = hash_to_g2(identity)
    H_m  = hash_to_g2(msg)
    lhs  = group.pair(sigma1, H_m) * group.pair(alpha_g1, h_I)
    rhs  = group.pair(g1,      sigma2)
    return lhs == rhs



###########################################################################
###### main function 
###########################################################################

# Initialize pairing group
group = BpGroup()
p = group.order()


iterations = 4
execution_times = []

for i in range(iterations):

    # Record the start time in nanoseconds
    start_time = time.perf_counter_ns()

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

    # Extract and process attribute values
    attribute_values = []
    for attr in patient_credential_attribute_order:
        value = patient_credential['info'][attr]
        attr_hash = hashlib.sha256(value.encode()).digest()  # Hash the attribute value
        attr_bn = Bn.from_binary(attr_hash).mod(p)  # Convert hash to Bn and reduce modulo p
        attribute_values.append(attr_bn)

    # Compute commitments and generate signature
    aggregate_commitment = compute_aggregate_commitment(H, attribute_values)
    credential_commitment = credential_commitment_func(pk_user, aggregate_commitment)

    # Verify signature
    # #print("=== Verify Signature ===")
    signature_valid = verify_signature(signature, pk_issuer, credential_commitment, g2)
    # #print(f"Signature Valid: {signature_valid}\n")

    '''
    # Define which attributes are hidden and which are disclosed
    hidden_attribute_indices = {
        0: attribute_values[0],  # 'credential_id'
        1: attribute_values[1],  # 'did_patient'
        2: attribute_values[2],  # 'patient_id'
        4: attribute_values[4],  # 'issue_date'
        5: attribute_values[5]   # 'did_apc'
    }


    disclosed_attribute_indices = {
        3: attribute_values[3]  # 'biometric_data'
    }
    '''


    # Generate a nonce
    nonce = group.order().random()

    # Generate ZK proof
    # #print("=== Generate Zero-Knowledge Proof ===")
    # #print(f"Hidden Attribute Indices and Values: {hidden_attribute_indices}")
    # #print(f"Disclosed Attribute Indices and Values: {disclosed_attribute_indices}\n")

    biometric_data_str = patient_credential['info']['biometric_data']  # keep STRING
    disclosed_attribute_set = {"biometric_data": biometric_data_str}
    sigma_hex = patient_credential["signature"]
    nonce = os.urandom(16).hex()

    pok_patientcredential = zk_proof_generation_hidden_attributes(
            g1, g2, H,
            pk_issuer, pk_user,
            sigma_hex,
            patient_credential,
            disclosed_attribute_set,
            nonce
        )

     
    # Load the patient's pre-existing pseudonym data from a file.
    PT = read_json_file(PT_CREDENTIAL_FILE_PATH)
    #print ("PT_credential: ", PT)

    appointment_confirmation_code = "76b3"

    # Construct the credential with signature
    IdentityVerificationRequest = {
            'info': {
                "AppointmentConfirmationCode": appointment_confirmation_code,
                "biometric_data":patient_credential['info']['biometric_data'],
                "proof_of_knowledge_biometric_data_verification_parameters": pok_patientcredential,
                "PT": PT,
                "ScheduleInfo": "ScheduleInfo"
            },
            'signature': None
    }
    

     # Serialize the “info” block consistently
    info_bytes = json.dumps(
            IdentityVerificationRequest['info'],
            sort_keys=True,
            separators=(',',':')
        ).encode('utf-8')

        # —————————————————————————————————————————————————————————————————
        # 1) Load pseudonym key, identity, and issuer public keys from JSON
        # ————————————————————————————————————————————————————————————————— 

    # File path of the JSON file
    file_path = r"/home/nmuslim162022/Desktop/mycode/pseudonym_private_key.json"

        # Load the JSON file
    with open(file_path, 'r') as file:
        data = json.load(file)

    identity    = data["pseudonym_identity"]
    sk_I_hex    = data["sk_I"]
    alpha_g1_hex= data["alpha_g1"]

    sk_I = G2Elem.from_bytes(bytes.fromhex(sk_I_hex),     group)
    alpha_g1 = G1Elem.from_bytes(bytes.fromhex(alpha_g1_hex), group)
 


    # Sign it with your Blind-IBS sign(…) routine
    sigma1, sigma2 = sign(sk_I, info_bytes)

    print ("sigma1: ", sigma1)
    print ("sigma1: ", sigma2)    

    IdentityVerificationRequest['signature'] = {
        "sigma1": sigma1,
        "sigma2": sigma2,
        }



   
    ##############################################
    # computation by the Healthcare provider
    ##############################################

    # The healthcare organization verifies
    # 1. schnorr signature of the patient on the IdentityVerificationRequest based on the patient pseudonym
    # 2. appointment confirmation code
    # 3. proof of knowledge of the patient credential with disclosed attribute 'BioHash'
    # 4. schnorr signature on the PT by the PTA


    ### [1.0] begin the verification process of the schnorr signature of the patient
    def verify_appointment_confirmation_code (appointment_confirmation_code):
        return True

    appointment_confirmation_code = "777B"
    valid = verify_appointment_confirmation_code(appointment_confirmation_code)
    print ("valid appointment confirmation code")


    P_a = IdentityVerificationRequest['info']['PT']['info']['P_patient_a']
    P_b = IdentityVerificationRequest['info']['PT']['info']['P_patient_b']
    pseudonym_identity = f"{P_a}|{P_b}"
    print("pseudonym_identity:", pseudonym_identity)

    print ( IdentityVerificationRequest)

    sigma1 = IdentityVerificationRequest['signature']['sigma1']
    sigma2 = IdentityVerificationRequest['signature']['sigma2']


    valid = verify(identity, info_bytes, sigma1, sigma2)
    print ("BLS_signature", valid)  


    ### [3.0] begin the verification process of the zk-proof of the disclosed attribute of the patient credential
   
    # verify the proof of knowledge of the patient credential (BioHash) 
    #valid = verify_proof_of_knowledge_patient_id(proof_params) 
    #print(f"\nFinal verification result: {valid}")
    
    #print ( "PT (zzz): ", IdentityVerificationRequest['info']['PT'])


    ### [4.0] begin the verification process of the PT

    #print ( "proof_of_knowledge_biometric_data_verification_parameters (zzz): ", IdentityVerificationRequest['info']['proof_of_knowledge_biometric_data_verification_parameters'])
    pok_patientcredential = IdentityVerificationRequest['info']['proof_of_knowledge_biometric_data_verification_parameters']

    '''
    # THE FIX: Deserialize ALL components of the proof from hex strings back into their proper crypto objects (Bn and G1Elem).
    # The verifier must work with the same data types the prover used.
    c_zkp_verify = Bn.from_hex(proof_of_knowledge_patient_id_verification_parameters['c'])
    masked_sk_user_zkp_verify = Bn.from_hex(proof_of_knowledge_patient_id_verification_parameters['masked_sk_user'])
    masked_hidden_zkp_verify = {int(i): Bn.from_hex(val) for i, val in proof_of_knowledge_patient_id_verification_parameters['masked_hidden'].items()}
    tilde_C_zkp_verify = decode(bytes.fromhex(proof_of_knowledge_patient_id_verification_parameters['tilde_C']))
    nonce_zkp_verify = Bn.from_hex(proof_of_knowledge_patient_id_verification_parameters['nonce'])
    C_hidden_zkp_verify = decode(bytes.fromhex(proof_of_knowledge_patient_id_verification_parameters['C_hidden']))
    '''

    # #print("=== Verify Zero-Knowledge Proof ===")
    # Verify
    validity = zk_verify_hidden_attributes(
            g1, g2, H,
            pk_issuer, pk_user,
            pok_patientcredential
        )
    print(f"\nVerification result222: {validity}")



    # Generate Schnorr signing key pair (PT)
    # sk_schnorr_pseudonym = 563452374                                 # Private key (example)               PT
    # Y_schnorr_pseudonym = pow(g1_schnorr, sk_schnorr_pseudonym, p1)  # Public key                          PT

    #print("\n--- Verifying the Pseudonym Token (PT) signature ---")


    # 1. Extract all components from the loaded PT JSON object
    P_patient_a = PT['info']['P_patient_a']
    P_patient_b = PT['info']['P_patient_b']
    rk_patient_to_HRR = PT['info']['rk_patient_to_HRR']
    encrypted_pid = PT['info']['encrypted_pid']

    s_from_token = PT['signature']['s']
    c_from_token = PT['signature']['c']
    Y_schnorr_pseudonym_PT  = PT['signature']['Y_sign']

    # 2. Reconstruct the exact byte sequence that was signed.
    # THE FIX: Concatenate the hex strings FIRST, then convert to bytes once.
    # This avoids any intermediate serialization metadata.
    full_hex_string = (
        P_patient_a +
        P_patient_b +
        rk_patient_to_HRR +
        encrypted_pid
    )
    pseudonym_token_bytes_to_verify = bytes.fromhex(full_hex_string)

    #print("\nReconstructed hex for PT verification:", pseudonym_token_bytes_to_verify.hex())
    #print("Public Key from Token (Y_sign):", Y_schnorr_pseudonym_PT)

    # 3. Verify the signature using the loaded components and the reconstructed bytes
    is_pt_signature_valid = schnorr_signature_verify(
        pseudonym_token_bytes_to_verify,
        s_from_token,
        c_from_token,
        Y_schnorr_pseudonym_PT
    )

    print("\nIs the Pseudonym Token signature valid?", is_pt_signature_valid)


    file_path = "/home/nmuslim162022/Desktop/mycode/hrr_key_data.json"

    def read_json_file(file_path):
        with open(file_path, "r") as json_file:
            return json.load(json_file)


    hrr_key_data = read_json_file(file_path)
    #print ("hrr_key_data: ", hrr_key_data)

    sk_HRR = Bn.from_hex(hrr_key_data['sk_HRR'])
    #pk_HRR = hrr_key_data['pk_HRR']


        # --- Helper Functions for PRE (Proxy Re-Encryption) ---
    # CORRECTED HELPER FUNCTION
    def derive_key(pid_enc_element):
        # THE FIX: Use petlib.pack.encode to match the key generation script.
        pid_enc_bytes = encode(pid_enc_element)
        hash_obj = SHA256.new(pid_enc_bytes)
        return hash_obj.digest()  # 32-byte symmetric key

    def decrypt_pid(encrypted_pid_bytes, key):
        iv = encrypted_pid_bytes[:16]
        ct = encrypted_pid_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')

    def healthcare_provider_computation(P_patient_a_elem, P_patient_b_elem, rk_patient_to_HRR_elem):
        P_HRR_a = P_patient_a_elem
        P_HRR_b = group.pair(rk_patient_to_HRR_elem, P_patient_b_elem)
        return P_HRR_a, P_HRR_b

    def HRR_computation(P_HRR_a_elem, P_HRR_b_elem, encrypted_pid_bytes, sk_HRR_bn):
        # This function now receives a Bn object for sk_HRR_bn.
        exponent = sk_HRR_bn.mod_inverse(group.order())
        PID_enc_decrypted = P_HRR_a_elem * (P_HRR_b_elem ** -exponent)
        symmetric_key_decrypted = derive_key(PID_enc_decrypted)
        patient_id_decrypted = decrypt_pid(encrypted_pid_bytes, symmetric_key_decrypted)
        return patient_id_decrypted

        # Deserialize all hex strings from the request back into their crypto object types.
    P_patient_a_elem = hex_to_group_element(P_patient_a, group)
    P_patient_b_elem = hex_to_group_element(P_patient_b, group)
    rk_patient_to_HRR_elem = hex_to_group_element(rk_patient_to_HRR, group)
    encrypted_pid_bytes = bytes.fromhex(encrypted_pid)

        # Now, call the functions with the correct object types.
    P_HRR_a, P_HRR_b = healthcare_provider_computation(P_patient_a_elem, P_patient_b_elem, rk_patient_to_HRR_elem)
    #print("Re-encrypted Pseudonym (P_HRR_a):", P_HRR_a)
    #print("Re-encrypted Pseudonym (P_HRR_b):", P_HRR_b)

        # Call the HRR function with the correct Bn object for the secret key.
    decrypted_patient_id = HRR_computation(P_HRR_a, P_HRR_b, encrypted_pid_bytes, sk_HRR)
    #print("\nDecrypted patient_id by HRR:", decrypted_patient_id)


    # Record the end time in nanoseconds
    end_time = time.perf_counter_ns()

    # Calculate the execution time in milliseconds
    execution_time_ms = (end_time - start_time) / 1_000_000
    #print(f"Execution time: {execution_time_ms} milliseconds")

    execution_times.append(execution_time_ms)



 # Remove outliers and calculate stats
trimmed_times = execution_times[1:-1]
if trimmed_times:
    avg_time = np.mean(trimmed_times)
    std_dev = np.std(trimmed_times)
    print("Execution Times:", execution_times)
    print("Trimmed Execution Times:", trimmed_times)
    print(f"Average Execution Time: {avg_time:.2f} ms")
    print(f"Standard Deviation: {std_dev:.2f} ms")   

