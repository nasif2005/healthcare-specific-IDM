# AppointmentBooking1.py   CLBilinear pairing signature scheme 
# # This code simulates the PATIENT's actions to book a healthcare appointment.
# # It constructs an `AppointmentScheduleRequest` by combining the patient's pseudonym,
# # a single-use Appointment Token (AT), and appointment details.
# # The entire request is then digitally signed using a key derived from the patient's pseudonym,
# # ensuring authenticity and non-repudiation. This signed request is what would be sent
# # to the healthcare provider for verification.

from bplib.bp import BpGroup
from petlib.pack import encode, decode
from petlib.bn import Bn
import hashlib
import json
import random
import string
import time
import numpy as np
from bplib.bp import BpGroup, G1Elem, G2Elem, Bn 
from Crypto.Hash import SHA256
from sympy import mod_inverse

# --- Public parameters for Appointment Token ---
p_AT = 23
q_AT = 11
g_AT = 2
h_AT = 3  # independent generator for Pedersen commitment


# APC key public key
Y_APC = 13

# --- Configuration ---
# File paths for the public parameters and the credential to be verified.
PT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/signed_pseudonym_token.json"
AT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT_credential_signature.json"
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"

def read_json_file(file_path):
    with open(file_path, "r") as json_file:
        return json.load(json_file)

def group_element_to_hex(element):
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)

def H_msg1_to_scalar(appointment_token_id: bytes) -> int:
    # Hash → Z_{q_AT} for the hidden attribute
    return H_to_q_bytes(appointment_token_id)



def H_to_q_bytes(*parts: bytes) -> int:
    h_ = hashlib.sha256()
    for part in parts:
        h_.update(part)
    return int.from_bytes(h_.digest(), "big") % q_AT


def int_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")




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




def hash_and_reduce(attribute_string, group_order):
    """Hashes a string attribute and reduces it to a number in the finite field."""
    attribute_hash = hashlib.sha256(str(attribute_string).encode()).digest()
    return Bn.from_binary(attribute_hash).mod(group_order)


def recompute_at_commitment(pk_user, H, at_info, group_order):
    """
    Recomputes the commitment value from the public attributes of the AT.
    This function must be identical on both the issuer's and verifier's side.
    """
    # Hash the appointment token ID to a scalar.
    m_token = hash_and_reduce(at_info['appointment_token_id'], group_order)
    # C_token = pk_user + m_token * H_0
    commitment_token = pk_user + H[0].mul(m_token)
    
    # Hash the expiration date to a scalar.
    m_exp = hash_and_reduce(at_info['expiration_date'], group_order)
    # C_exp = m_exp * H_1
    commitment_exp_date = H[1].mul(m_exp)
    
    # The final commitment is the sum of the individual commitments.
    return commitment_token + commitment_exp_date

# --- Core Verification Logic ---

def verify_at_signature(signature_elem, commitment_elem, pk_issuer_elem, group):
    """
    Verifies the AT signature using a bilinear pairing equation.
    
    The signature was created as: sig = commitment * sk_issuer
    The verification equation is: e(sig, g2) == e(commitment, pk_issuer)
    where pk_issuer = g2 * sk_issuer. This works due to the bilinearity of pairings.
    """
    # Get the public generator for group G2.
    g2 = group.gen2()
    
    # Calculate the Left-Hand Side (LHS) of the pairing equation.
    # LHS = e(signature, g2)
    lhs = group.pair(signature_elem, g2)
    
    # Calculate the Right-Hand Side (RHS) of the pairing equation.
    # RHS = e(commitment, pk_issuer)
    rhs = group.pair(commitment_elem, pk_issuer_elem)
    
    # The signature is valid if and only if the two pairing results are equal.
    return lhs == rhs


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





# Initialize the elliptic curve group (BN254 is the default).
group = BpGroup()
p = group.order()


iterations = 1
execution_times = []

for i in range(iterations):

        # Record the start time in nanoseconds
        start_time = time.perf_counter_ns()

        # --- Load Data and Derive Keys ---

        # Load the patient's pre-existing pseudonym data from a file.
        patient_pseudonym_data = read_json_file(PT_CREDENTIAL_FILE_PATH)
        #print("patient_pseudonym_data: ", patient_pseudonym_data)

        # Deserialize the hex strings from the file back into elliptic curve group elements
        # These objects are needed for the cryptographic operations.
        P_patient_a_obj = hex_to_group_element(patient_pseudonym_data['info']['P_patient_a'], group)
        P_patient_b_obj = hex_to_group_element(patient_pseudonym_data['info']['P_patient_b'], group)
        
        # These values are already strings/hex, so we just load them.
        rk_patient_to_HRR_str = patient_pseudonym_data['info']['rk_patient_to_HRR']
        encrypted_pid_str = patient_pseudonym_data['info']['encrypted_pid']

        """
        print("P_patient_a (object): ", P_patient_a_obj)
        print("P_patient_b (object): ", P_patient_b_obj)
        print("rk_patient_to_HRR (string): ", rk_patient_to_HRR_str)
        print("encrypted_pid (string): ", encrypted_pid_str)
        """

        # --- Derive the Schnorr Signing Key from the Pseudonym ---
        # A unique private key for this transaction is derived from the pseudonym itself.
        
        AT = read_json_file(AT_CREDENTIAL_FILE_PATH)
        #print ("AT_credential: ", AT)


        # --- Construct and Sign the AppointmentScheduleRequest ---

        # Get the hexadecimal string representations of your group elements.
        # This is necessary because raw crypto objects cannot be converted to JSON.
        P_patient_a_hex = group_element_to_hex(P_patient_a_obj)
        P_patient_b_hex = group_element_to_hex(P_patient_b_obj)

        # Assemble the main body (the 'info' part) of the request.
        # THE FIX IS HERE: Use the hex string representations, NOT the raw objects.
        AppointmentScheduleRequest = {
            'info': {
                "Ppatient": [P_patient_a_hex, P_patient_b_hex],
                "rkpatient_to_HRR": rk_patient_to_HRR_str,
                "ctPID": encrypted_pid_str,
                "AT": AT,
                "ScheduleInfo": "schedule_info"
            },
            'signature': None
        }

        # Serialize the “info” block consistently
        info_bytes = json.dumps(
            AppointmentScheduleRequest['info'],
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

        sk_I     = G2Elem.from_bytes(bytes.fromhex(sk_I_hex),     group)
        alpha_g1 = G1Elem.from_bytes(bytes.fromhex(alpha_g1_hex), group)

        # Sign it with your Blind-IBS sign(…) routine
        sigma1, sigma2 = sign(sk_I, info_bytes)

        print ("sigma1: ", sigma1)
        print ("sigma1: ", sigma2)

        #valid = verify(identity, info_bytes, sigma1, sigma2)
        #print (valid)
           
        AppointmentScheduleRequest['signature'] = {
        "sigma1": sigma1,
        "sigma2": sigma2,
        }




    ##############################################
    # computation by the Healthcare provider
    ##############################################

    # Healthcare provider verify 
    # 1. signature of the patient on the AppointmentScheduleRequest based on schnorr signature scheme 
    # 2. signature of the AT based on CL(RSA) signature scheme

        appointment_token_id_str = AppointmentScheduleRequest["info"]["AT"]["info"]["appointment_token_id"]
        expiration_date_str = AppointmentScheduleRequest["info"]["AT"]["info"]["expiration_date"]

        print ("appointment_token_id_str: ", appointment_token_id_str)
        print ("expiration_date_str: ", expiration_date_str)

        # Signature components (could be strings in JSON)
        c = int(AppointmentScheduleRequest["info"]["AT"]["signature"]["c"])
        s = int(AppointmentScheduleRequest["info"]["AT"]["signature"]["s"])
        t = int(AppointmentScheduleRequest["info"]["AT"]["signature"]["t"])
        
        print (c)
        print (s)
        print (t)

        # Convert to bytes for hashing
        appointment_token_id_bytes = appointment_token_id_str.encode("utf-8")
        expiration_date_bytes = expiration_date_str.encode("utf-8")

        # Verify (note: function expects sig=(s, c) in that order)
        is_valid = verify_appointment_token_signature(
            Y_APC=Y_APC,
            appointment_token_id=appointment_token_id_bytes,
            expiration_date=expiration_date_bytes,
            sig=(s, c),
            t=t
        )

        print("Signature verification:", "VALID" if is_valid else "INVALID")


        characters = string.ascii_letters + string.digits  # Letters and digits
        appointment_confirmation_code = ''.join(random.choice(characters) for _ in range(6))    

        print ("appointment_confirmation_code: ", appointment_confirmation_code)    

    
        # Record the end time in nanoseconds
        end_time = time.perf_counter_ns()

        # Calculate the execution time in milliseconds
        execution_time_ms = (end_time - start_time) / 1_000_000
        #print(f"Execution time: {execution_time_ms} milliseconds")

        execution_times.append(execution_time_ms)


'''
# Remove outliers and calculate stats
trimmed_times = execution_times[1:-1]
if trimmed_times:
    avg_time = np.mean(trimmed_times)
    std_dev = np.std(trimmed_times)
    print("Execution Times:", execution_times)
    print("Trimmed Execution Times:", trimmed_times)
    print(f"Average Execution Time: {avg_time:.2f} ms")
    print(f"Standard Deviation: {std_dev:.2f} ms") 

'''   