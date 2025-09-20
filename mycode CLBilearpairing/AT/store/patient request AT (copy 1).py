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
        print(f"Error: File not found at {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON file at {file_path}")
        return None


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


# --- Zero-Knowledge Proof Generation ---
def generate_hidden_attribute_zk_proof(H, sk_user, hidden_attributes, nonce):
    """
    Generates a zero-knowledge proof for hidden attributes.
    """
    tilde_sk_user = group.order().random()
    tilde_m = {i: group.order().random() for i in hidden_attributes}

    tilde_C = tilde_sk_user * group.gen1()
    for i, m_i in hidden_attributes.items():
        tilde_C += tilde_m[i] * H[i]

    tilde_C_serialized = tilde_C.export()
    nonce_serialized = encode(nonce)
    data_to_hash = tilde_C_serialized + nonce_serialized
    c = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    masked_sk_user = tilde_sk_user + (c * sk_user)
    masked_hidden = {i: tilde_m[i] + (c * m_i) for i, m_i in hidden_attributes.items()}

    return c, masked_sk_user, masked_hidden, tilde_C


# --- Zero-Knowledge Proof Verification ---
def verify_hidden_attribute_zk_proof(c, masked_sk_user, masked_hidden, tilde_C, H, nonce, C_hidden, g1):
    """
    Verifies a zero-knowledge proof for hidden attributes.
    """
    term1 = masked_sk_user * g1
    term2 = G1Elem.inf(group)
    for i, s_hidden_i in masked_hidden.items():
        term2 += s_hidden_i * H[i]

    cC = C_hidden * c
    tilde_C_prime = term1 + term2 - cC

    tilde_C_prime_serialized = tilde_C_prime.export()
    nonce_serialized = encode(nonce)
    data_to_hash = tilde_C_prime_serialized + nonce_serialized
    c_prime = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    return c == c_prime


def generate_proof_of_knowledge_patient_id_verification_parameters():
    """
    Generates all necessary cryptographic objects and returns them in a single dictionary.
    """
    patient_credential = read_json_file(PATIENT_CREDENTIAL_FILE_PATH)
    parameters = read_json_file(PARAMETERS_FILE_PATH)
    if not patient_credential or not parameters:
        return None

    # Load and deserialize all necessary cryptographic objects
    signature = decode(bytes.fromhex(patient_credential['signature']))
    g1 = decode(bytes.fromhex(parameters['g1']))
    g2 = decode(bytes.fromhex(parameters['g2']))
    H = [decode(bytes.fromhex(h)) for h in parameters['H']]
    pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
    sk_user = Bn.from_hex(parameters['sk_user'])
    pk_user = decode(bytes.fromhex(parameters['pk_user']))

    # Process attributes and create commitments
    attribute_values = []
    for attr in ATTRIBUTE_ORDER:
        value = patient_credential['info'][attr]
        attr_hash = hashlib.sha256(value.encode()).digest()
        attr_bn = Bn.from_binary(attr_hash).mod(p)
        attribute_values.append(attr_bn)

    aggregate_commitment = compute_aggregate_commitment(H, attribute_values)
    credential_commitment = credential_commitment_func(pk_user, aggregate_commitment)

    # Generate the Zero-Knowledge Proof
    hidden_attribute_indices = {
        0: attribute_values[0], 1: attribute_values[1], 3: attribute_values[3],
        4: attribute_values[4], 5: attribute_values[5]
    }
    nonce = group.order().random()
    c, masked_sk_user, masked_hidden, tilde_C = generate_hidden_attribute_zk_proof(
        H, sk_user, hidden_attribute_indices, nonce
    )
    C_hidden = (sk_user * g1)
    for i, m_i in hidden_attribute_indices.items():
        C_hidden += H[i] * m_i

    # Return a single dictionary containing all the live cryptographic objects.
    return {
        "signature": signature, "pk_issuer": pk_issuer,
        "credential_commitment": credential_commitment, "g2": g2, "g1": g1,
        "c": c, "masked_sk_user": masked_sk_user, "masked_hidden": masked_hidden,
        "tilde_C": tilde_C, "H": H, "nonce": nonce, "C_hidden": C_hidden,
        "disclosed_attributes": patient_credential['info']['patient_id']
    }


#############################
# Main Execution Block      #
#############################

# Record the start time
start_time = time.perf_counter_ns()

# Generate a single dictionary containing all proof parameters as crypto objects
proof_objects = generate_proof_of_knowledge_patient_id_verification_parameters()

if proof_objects:
    # --- 1. Perform local Zero-Knowledge Proof verification ---
    print("\n=== Performing Local ZKP Verification ===")
    is_zkp_valid = verify_hidden_attribute_zk_proof(
        proof_objects['c'], proof_objects['masked_sk_user'], proof_objects['masked_hidden'],
        proof_objects['tilde_C'], proof_objects['H'], proof_objects['nonce'],
        proof_objects['C_hidden'], proof_objects['g1']
    )
    print(f"Zero-Knowledge Proof is Valid: {is_zkp_valid}")
    
    # --- 2. Perform local signature verification ---
    print("\n=== Performing Local Signature Verification ===")
    signature_valid = verify_signature(
        proof_objects['signature'], proof_objects['pk_issuer'],
        proof_objects['credential_commitment'], proof_objects['g2']
    )
    print(f"Signature Valid: {signature_valid}")

    # --- 3. (Optional) If all checks pass, create the payload and send to the server ---
    if is_zkp_valid and signature_valid:
        print("\n=== All local checks passed. Preparing to send request to server... ===")

 

        # Uncomment the following block to send the request
        '''
        try:
            print(f"Sending POST request to {apc_url}")
            # print("Payload:", json.dumps(payload_for_server, indent=2))
            response = requests.post(apc_url, json=payload_for_server)
            response.raise_for_status()
            
            print("Request successful. Server response:")
            print(response.json())

        except requests.exceptions.RequestException as e:
            print(f"\nAn error occurred while contacting the server: {e}")
        '''

# Record the end time and calculate duration
end_time = time.perf_counter_ns()
execution_time_ms = (end_time - start_time) / 1_000_000
print(f"\nTotal execution time: {execution_time_ms:.2f} milliseconds")