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


# File paths
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT/crypto_parameters.json"
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT/patient_credential_signature.json"

# URL of the APC server
apc_url = 'http://127.0.0.1:4000/request_AT_credential_signature'

# Define the fixed attribute order (must match the server)
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']

# Initialize pairing group
group = BpGroup()
p = group.order()

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


# --- Zero-Knowledge Proof Generation ---
def generate_hidden_attribute_zk_proof(H, sk_user, hidden_attributes, nonce):
    """
    Generates a zero-knowledge proof for hidden attributes.
    """
    # Step 1: Generate random blinding factors
    tilde_sk_user = group.order().random()
    tilde_m = {i: group.order().random() for i in hidden_attributes}

    # Step 2: Compute the blinded commitment
    tilde_C = tilde_sk_user * group.gen1()
    for i, m_i in hidden_attributes.items():
        tilde_C += tilde_m[i] * H[i]  # Ensure H[i] is a G1Elem

    # Step 3: Generate challenge using the hash function
    tilde_C_serialized = tilde_C.export()
    nonce_serialized = encode(nonce)  # Serialize nonce as bytes
    data_to_hash = tilde_C_serialized + nonce_serialized
    c = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    # Step 4: Compute the responses
    masked_sk_user = tilde_sk_user + (c * sk_user)
    masked_hidden = {i: tilde_m[i] + (c * m_i) for i, m_i in hidden_attributes.items()}

    # #print("[DEBUG] Proof Generation")
    # #print(f"  tilde_C: {tilde_C}")
    # #print(f"  Challenge (c): {c}")
    # #print(f"  Masked sk_user: {masked_sk_user}")
    # #print(f"  Masked Hidden Attributes: {masked_hidden}")
    # #print(f"Generated Challenge (c): {c}")

    return c, masked_sk_user, masked_hidden, tilde_C


# --- Zero-Knowledge Proof Verification ---
def verify_hidden_attribute_zk_proof(c, masked_sk_user, masked_hidden, tilde_C, H, nonce, C_hidden, g1):
    """
    Verifies a zero-knowledge proof for hidden attributes.

    Implements the following verification steps:
    1. Recompute the blinded commitment using responses.
    2. Recompute the challenge as Hash(recomputed_commitment || nonce).
    3. Check if recomputed challenge matches the provided challenge.

    :param c: Challenge (Bn).
    :param masked_sk_user: Response for sk_user (Bn).
    :param masked_hidden: Dict mapping attribute indices to their responses (Bn).
    :param tilde_C: Original blinded commitment (G1Elem).
    :param H: List of attribute generators (G1Elem).
    :param nonce: Bn representing a nonce.
    :param C_hidden: Partial credential commitment for hidden attributes (G1Elem).
    :param g1: Generator for G1 (G1Elem).
    :return: Boolean indicating validity.
    """
    # Step 1: Recompute the blinded commitment using responses
    term1 = masked_sk_user * g1
    # #print(f"  [DEBUG] term1 (s_sk_user * g1): {term1}")

    term2 = G1Elem.inf(group)
    for i, s_hidden_i in masked_hidden.items():
        tmp = s_hidden_i * H[i]
        # #print(f"  [DEBUG] term2 partial (s_hidden[{i}] * H[{i}]): {tmp}")
        term2 += tmp
    # #print(f"  [DEBUG] term2 (sum of s_hidden[i] * H[i]): {term2}")

    cC = C_hidden * c
    # #print(f"  [DEBUG] cC (c * C_hidden): {cC}")

    tilde_C_prime = term1 + term2 - cC
    # #print(f"  [DEBUG] tilde_C_prime: {tilde_C_prime}")

    # Step 2: Recompute the challenge
    tilde_C_prime_serialized = tilde_C_prime.export()
    nonce_serialized = encode(nonce)
    data_to_hash = tilde_C_prime_serialized + nonce_serialized
    c_prime = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    # #print("[DEBUG] Proof Verification")
    # #print(f"  Original Challenge (c): {c}")
    # #print(f"  Recomputed Challenge (c'): {c_prime}")

    # Step 3: Validate the proof
    is_valid = c == c_prime
    # #print(f"  Zero-Knowledge Proof Valid: {is_valid}")
    return is_valid


def hash_and_reduce(attribute, n):
    """Hash an attribute and reduce modulo n."""
    attribute_hash = hashlib.sha256(attribute.encode()).hexdigest()
    attribute_bn = Bn.from_hex(attribute_hash)  # Safely handle large hash values
    return attribute_bn % n



def generate_zk_proof_for_appointment_id(appointment_token_id, nonce):
    """
    Generate a ZKP proving knowledge of sk_user and appointment_token_id.
    Returns a dictionary containing:
    - H_appointment_token_id
    - challenge c
    - masked_sk_user
    - masked_appointment_token_id
    - nonce
    """
    r = group.order()

    # Access global variables
    global g1, pk_user, H

    # Step 1: Select random blinding factors
    sk_user_prime = r.random()                     # blinded sk_user
    appointment_token_id_prime = r.random()        # blinded attribute 'appointment_token_id'

    pk_user_prime = sk_user_prime * g1

    # Convert appointment_token_id to a Bn using hash_and_reduce
    appointment_token_bn = hash_and_reduce(appointment_token_id, p)

    # Compute the original credential commitment based on pk_user and appointment_token_bn
    H_appointment_token_id = pk_user + appointment_token_bn * H[0]

    # Compute the blinded commitment for the appointment token
    H_prime_appointment_token_id = pk_user_prime + appointment_token_id_prime * H[0]

    # Step 4: Generate the challenge c = Hash(H_appointment_token_id || H_prime_appointment_token_id || nonce)
    def serialize(elem):
        return encode(elem)
    
    data_to_hash = serialize(H_appointment_token_id) + serialize(H_prime_appointment_token_id) + serialize(nonce)
    c = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(r)

    # Step 5: Compute responses
    masked_sk_user = sk_user_prime + c * sk_user
    masked_appointment_token_id = appointment_token_id_prime + c * appointment_token_bn

    return {
        'H_appointment_token_id': H_appointment_token_id,
        'c': c,
        'masked_sk_user': masked_sk_user,
        'masked_appointment_token_id': masked_appointment_token_id,
        'nonce': nonce
    }


def verify_zk_proof_for_appointment_and_key(proof):
    """
    Verify the ZKP proving knowledge of sk_user and appointment_token_id.
    """
    r = group.order()

    # Access global variables
    global g1, pk_user, H

    H_appointment_token_id = proof['H_appointment_token_id']
    c = proof['c']
    masked_sk_user = proof['masked_sk_user']
    masked_appointment_token_id = proof['masked_appointment_token_id']
    nonce = proof['nonce']

    # Step 1: Reconstruct the blinded attribute commitment part
    H_appointment_token_id_tilde = masked_appointment_token_id * H[0]

    # Step 2: Reconstruct the blinded public key part
    pk_user_prime = masked_sk_user * g1

    # Step 3: Reconstruct H' using the responses and subtracting c*H_appointment_token_id
    H_appointment_token_id_tilde_prime = pk_user_prime + H_appointment_token_id_tilde - c * H_appointment_token_id

    # Step 4: Recompute challenge c'
    def serialize(elem):
        return encode(elem)
    
    data_to_hash = serialize(H_appointment_token_id) + serialize(H_appointment_token_id_tilde_prime) + serialize(nonce)
    c_prime = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(r)

    return c == c_prime





#############################
# Main Function             #
#############################

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
for attr in ATTRIBUTE_ORDER:
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

# Define which attributes are hidden and which are disclosed
hidden_attribute_indices = {
    0: attribute_values[0],  # 'serial_number'
    1: attribute_values[1],  # 'biometric_data'
    3: attribute_values[3],  # 'issue_date'
    4: attribute_values[4],  # 'issue_date'
    5: attribute_values[5]  # 'issue_date'
}

disclosed_attribute_indices = {
    2: attribute_values[2]  # 'patient_id'
}

# #print("=== Generate Zero-Knowledge Proof ===")
# #print(f"Hidden Attribute Indices and Values: {hidden_attribute_indices}")
# #print(f"Disclosed Attribute Indices and Values: {disclosed_attribute_indices}\n")

# Generate a nonce
nonce = group.order().random()
# #print(f"Nonce: {nonce}\n")

# Generate ZK proof
c, masked_sk_user, masked_hidden, tilde_C = generate_hidden_attribute_zk_proof(
    H, sk_user, hidden_attribute_indices, nonce
)

# #print("=== Generate Zero-Knowledge Proof ===")
# #print(f"Hidden Attribute Indices and Values: {hidden_attribute_indices}")
# #print(f"Disclosed Attribute Indices and Values: {disclosed_attribute_indices}\n")

# Compute partial credential commitment for hidden attributes
C_hidden = (sk_user * g1)
for i, m_i in hidden_attribute_indices.items():
    C_hidden += H[i] * m_i
# #print(f"[DEBUG] Partial Credential Commitment (C_hidden): {C_hidden}\n")

# Verify ZK proof
# #print("=== ✨ ===")
# #print("c: ", c)
# #print("masked_sk_user: ", masked_sk_user)
# #print("masked_hidden: ", masked_hidden)
# #print("tilde_C: ", tilde_C)
# #print("H: ", H)
# #print("nonce: ", nonce)
# #print("C_hidden: ", C_hidden)
# #print("g1: ", g1)
# #print("=== Verify Zero-Knowledge Proof ===")
zk_valid = verify_hidden_attribute_zk_proof(
    c, masked_sk_user, masked_hidden, tilde_C, H, nonce, C_hidden, g1
)

proof_of_knowledge_patient_id_verification_parameters = {
    'signature': encode(signature).hex(),  # Serialize G1Elem to hex
    'credential_commitment': encode(credential_commitment).hex(),  # Serialize G1Elem to hex
    'c': c.hex(),  # Serialize Bn to hex
    'masked_sk_user': masked_sk_user.hex(),  # Serialize Bn to hex
    'masked_hidden': {i: val.hex() for i, val in masked_hidden.items()},  # Serialize Bn dict to hex
    'tilde_C': encode(tilde_C).hex(),  # Serialize G1Elem to hex
    'H': [encode(h).hex() for h in H],  # Serialize list of G1Elem to hex
    'nonce': nonce.hex(),  # Serialize Bn to hex
    'C_hidden': encode(C_hidden).hex(),  # Serialize G1Elem to hex
    'disclosed_attributes': patient_credential['info']['patient_id'],  # Leave as-is
}

# # #print("Serialized Proof Data:", json.dumps(proof_of_knowledge_verification_parameters, indent=4))

# Appointment token ID as a string
appointment_token_id = '8ff59cf4-6224-4644-8c65-88d0143dded4'

# Generate a random nonce
nonce = group.order().random()

# Generate ZKP
zk_proof_appointment_token_id_attribute = generate_zk_proof_for_appointment_id(appointment_token_id, nonce)

# Verify ZKP
#is_valid = verify_zk_proof_for_appointment_and_key(zk_proof_appointment_token_id_attribute)
#print(f"ZKP valid *: {is_valid}")
### ### ###



# Ensure the keys are strings or other hashable types
payload = {
    'zk_proof_appointment_token_id_attribute': encode(zk_proof_appointment_token_id_attribute).hex(),  # Serialize G1Elem to hex
    'proof_of_knowledge_patient_id_verification_parameters': proof_of_knowledge_patient_id_verification_parameters
}

iterations = 12
execution_times = []

for i in range(iterations):

    # Record the start time in nanoseconds
    start_time = time.perf_counter_ns()

    # Send request to the Healthcare Organization API
    response = requests.post(apc_url, json=payload)
    AT_credential = response.json()  # Convert the list to a dictionary
    AT_credential['info']['appointment_token_id'] = appointment_token_id

    # #print("AT_credential***: ", AT_credential)

    signature_bytes = bytes.fromhex(AT_credential['signature'])
    # Attempt to decode into G1Elem
    signature = G1Elem.from_bytes(signature_bytes, group)
    signature_hex = signature.export().hex()
    # #print("Signature (hex):", signature_hex)

    # Write the dictionary to a JSON file
    with open(r'/home/nmuslim162022/Desktop/mycode2/AT/AT_credential_signature.json', 'w') as json_file:
        json.dump(AT_credential, json_file, indent=4)

    # Record the end time in nanoseconds
    end_time = time.perf_counter_ns()

    # Calculate the execution time in milliseconds
    execution_time_ms = (end_time - start_time) / 1_000_000
    #print(f"Execution time: {execution_time_ms} milliseconds")

    execution_times.append(execution_time_ms)

    time.sleep(5)  # Sleep for 5 seconds before the next


# Remove outliers and calculate stats
trimmed_times = execution_times[1:-1]
if trimmed_times:
    avg_time = np.mean(trimmed_times)
    std_dev = np.std(trimmed_times)
    print("Execution Times:", execution_times)
    print("Trimmed Execution Times:", trimmed_times)
    print(f"Average Execution Time: {avg_time:.2f} ms")
    print(f"Standard Deviation: {std_dev:.2f} ms")   