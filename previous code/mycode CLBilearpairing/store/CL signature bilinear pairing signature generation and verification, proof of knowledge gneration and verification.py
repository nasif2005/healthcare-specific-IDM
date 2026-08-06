from collections import OrderedDict
from datetime import datetime
from bplib.bp import BpGroup
from petlib.pack import encode, decode
from petlib.bn import Bn
import hashlib
import json
from bplib.bp import G1Elem
import time
import numpy as np

# --- Public Parameters Setup ---
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']

apc_did = "did:example:apc123"  # DID of the APC
patient_did = "did:example:patient123"  # DID of the patient


# Initialize pairing group (using BN254 by default in bplib)
group = BpGroup()
p = group.order()  # Prime order of the group



# Load the public key components
FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"
with open(FILE_PATH, 'r') as f:
    parameters = json.load(f)

g1 = decode(bytes.fromhex(parameters['g1']))
g2 = decode(bytes.fromhex(parameters['g2']))
H = [decode(bytes.fromhex(h)) for h in parameters['H']]
sk_issuer = Bn.from_hex(parameters['sk_issuer'])
pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
sk_user = Bn.from_hex(parameters['sk_user'])
pk_user = decode(bytes.fromhex(parameters['pk_user']))


def hash_and_reduce(attribute, n):
    """Hash an attribute and reduce modulo n."""
    attribute_hash = hashlib.sha256(attribute.encode()).hexdigest()
    attribute_bn = Bn.from_hex(attribute_hash)  # Safely handle large hash values
    return attribute_bn % n


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


# --- Signature ---
def generate_signature(issuer_sk, credential_commitment):
    """Generate a signature using the issuer's private key."""
    return credential_commitment.mul(issuer_sk)


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

    #print("[DEBUG] Proof Generation")
    #print(f"  tilde_C: {tilde_C}")
    #print(f"  Challenge (c): {c}")
    #print(f"  Masked sk_user: {masked_sk_user}")
    #print(f"  Masked Hidden Attributes: {masked_hidden}")

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
    #print(f"  [DEBUG] term1 (s_sk_user * g1): {term1}")

    term2 = G1Elem.inf(group)
    for i, s_hidden_i in masked_hidden.items():
        tmp = s_hidden_i * H[i]
        #print(f"  [DEBUG] term2 partial (s_hidden[{i}] * H[{i}]): {tmp}")
        term2 += tmp
    #print(f"  [DEBUG] term2 (sum of s_hidden[i] * H[i]): {term2}")

    cC = C_hidden * c
    #print(f"  [DEBUG] cC (c * C_hidden): {cC}")

    tilde_C_prime = term1 + term2 - cC
    #print(f"  [DEBUG] tilde_C_prime: {tilde_C_prime}")

    # Step 2: Recompute the challenge
    tilde_C_prime_serialized = tilde_C_prime.export()
    nonce_serialized = encode(nonce)
    data_to_hash = tilde_C_prime_serialized + nonce_serialized
    c_prime = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    #print("[DEBUG] Proof Verification")
    #print(f"  Original Challenge (c): {c}")
    #print(f"  Recomputed Challenge (c'): {c_prime}")

    # Step 3: Validate the proof
    is_valid = c == c_prime
    #print(f"  Zero-Knowledge Proof Valid: {is_valid} 🥣")
    return is_valid



####################
# Main function   #
####################
# Arrays to store execution times
execution_times_signature_generation = []
execution_times_signature_verification = []
execution_times_proof_generation = []
execution_times_proof_verification = []

# Arrays to store execution times
execution_times_signature_generation = []
execution_times_signature_verification = []
execution_times_proof_generation = []
execution_times_proof_verification = []

for i in range(1):  # Adjust iteration count as needed
    #print(f"Iteration 🧁 {i + 1}")

    # $a$ - Signature Generation
    start_time = time.perf_counter_ns()
    # Generate the patient credential
    patient_credential = OrderedDict({
        'info': {
                'credential_id': 'SN-0001',
                'did_patient': patient_did,
                'patient_id': "PT-0001",
                'biometric_data': 'base64_encoded_image_data',
                'issue_date': datetime.now().strftime("%Y-%m-%d"),
                'did_apc': apc_did,
        }
    })

    # Generate attribute values based on ATTRIBUTE_ORDER
    attribute_values = [
        hash_and_reduce(str(patient_credential['info'][attr]), p) for attr in ATTRIBUTE_ORDER
    ]

    # Compute commitments and generate signature
    aggregate_commitment = compute_aggregate_commitment(H, attribute_values)
    credential_commitment = credential_commitment_func(pk_user, aggregate_commitment)
    signature = generate_signature(sk_issuer, credential_commitment)
    patient_credential['signature'] = signature.export().hex()
    end_time = time.perf_counter_ns()
    execution_time_ms_signature_generation = (end_time - start_time) / 1_000_000
    execution_times_signature_generation.append(execution_time_ms_signature_generation)

    # $b$ - Signature Verification
    start_time = time.perf_counter_ns()
    verify_signature(signature, pk_issuer, credential_commitment, g2)
    end_time = time.perf_counter_ns()
    execution_time_ms_signature_verification = (end_time - start_time) / 1_000_000
    execution_times_signature_verification.append(execution_time_ms_signature_verification)

    # Define hidden and disclosed attributes
    hidden_attribute_indices = {1: attribute_values[1]}  # Example hidden attribute
    nonce = group.order().random()

    # $c$ - Proof Generation
    start_time = time.perf_counter_ns()
    c, masked_sk_user, masked_hidden, tilde_C = generate_hidden_attribute_zk_proof(
        H, sk_user, hidden_attribute_indices, nonce
    )
    end_time = time.perf_counter_ns()
    execution_time_ms_proof_generation = (end_time - start_time) / 1_000_000
    execution_times_proof_generation.append(execution_time_ms_proof_generation)

    # Compute partial credential commitment for hidden attributes
    C_hidden = (sk_user * g1)
    for i, m_i in hidden_attribute_indices.items():
        C_hidden += H[i] * m_i

    # $d$ - Proof Verification
    start_time = time.perf_counter_ns()
    verify_hidden_attribute_zk_proof(
        c, masked_sk_user, masked_hidden, tilde_C, H, nonce, C_hidden, g1
    )
    end_time = time.perf_counter_ns()
    execution_time_ms_proof_verification = (end_time - start_time) / 1_000_000
    execution_times_proof_verification.append(execution_time_ms_proof_verification)

    time.sleep(2)  # Ensure all threads complete before exiting

# Drop the first and last values from each array
trimmed_gen_times = execution_times_signature_generation[1:-1]
trimmed_ver_times = execution_times_signature_verification[1:-1]
trimmed_proof_gen_times = execution_times_proof_generation[1:-1]
trimmed_proof_ver_times = execution_times_proof_verification[1:-1]

# Calculate average and standard deviation for each operation
gen_avg = np.mean(trimmed_gen_times)
gen_std = np.std(trimmed_gen_times)
ver_avg = np.mean(trimmed_ver_times)
ver_std = np.std(trimmed_ver_times)
proof_gen_avg = np.mean(trimmed_proof_gen_times)
proof_gen_std = np.std(trimmed_proof_gen_times)
proof_ver_avg = np.mean(trimmed_proof_ver_times)
proof_ver_std = np.std(trimmed_proof_ver_times)

# Print results
print("Execution Times for Signature Generation:", execution_times_signature_generation)
print("Trimmed Generation Times:", trimmed_gen_times)
print(f"Average Generation Time: {gen_avg:.2f} ms, Standard Deviation: {gen_std:.2f} ms")

print("Execution Times for Signature Verification:", execution_times_signature_verification)
print("Trimmed Verification Times:", trimmed_ver_times)
print(f"Average Verification Time: {ver_avg:.2f} ms, Standard Deviation: {ver_std:.2f} ms")

print("Execution Times for Proof Generation:", execution_times_proof_generation)
print("Trimmed Proof Generation Times:", trimmed_proof_gen_times)
print(f"Average Proof Generation Time: {proof_gen_avg:.2f} ms, Standard Deviation: {proof_gen_std:.2f} ms")

print("Execution Times for Proof Verification:", execution_times_proof_verification)
print("Trimmed Proof Verification Times:", trimmed_proof_ver_times)
print(f"Average Proof Verification Time: {proof_ver_avg:.2f} ms, Standard Deviation: {proof_ver_std:.2f} ms")

