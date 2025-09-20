

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
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/patient_credential_signature.json"


# Define the fixed attribute order (must match the server)
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']

# Initialize pairing group
group = BpGroup()
p = group.order()


# --- Public Parameters ---
g1 = group.gen1()
g2 = group.gen2()
z = group.pair(g1, g2)

# --- Key Generation ---
sk_patient = group.order().random()
pk_patient = g2 * sk_patient

sk_HRR = group.order().random()
pk_HRR = g1 * sk_HRR

# Define discrete log group parameters for Schnorr signature
p1 = 162259276829213363391578010288127  # A large prime number
q1 = 81129638414606681695789005144063   # A prime divisor of p1 - 1
g1_schnorr = 2  # Generator for the subgroup of order q1

# Generate Schnorr signing key pair
x_sign = 563452374  # Private key (example)
Y_sign = pow(g1_schnorr, x_sign, p1)  # Public key






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




# ==============================================================================
# 3. NIZK PROOF IMPLEMENTATION (APPENDIX A)
# ==============================================================================

def generate_binding_proof(P_patient_a, P_patient_b, r, pk_patient, patient_id_str):
    """
    Generates a NIZK proof for binding the patient credential and pseudonym.
    """
    print("\n--- Generating NIZK Binding Proof (Patient's Side) ---")

    # 1. Choose random scalars t1, t2
    t1 = group.order().random()
    t2 = group.order().random()

    # 2. Compute commitments T1 (in GT) and T2 (in G2)
    T1 = z ** t1
    T2 = pk_patient * t2
    print("Step 1 & 2: Commitments T1, T2 generated.")

    # 3. Compute Fiat-Shamir challenge 'c'
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()

    hasher = hashlib.sha256()
    hasher.update(encode(P_patient_a))
    hasher.update(encode(P_patient_b))
    hasher.update(encode(T1))
    hasher.update(encode(T2))
    hasher.update(encode(pk_patient))
    hasher.update(encode(patient_id_fr))
    
    c = Bn.from_hex(hasher.hexdigest()) % group.order()
    print(f"Step 3: Fiat-Shamir Challenge 'c' computed.")

    # 4. Compute responses s1, s2
    s1 = (t1 + c * r) % group.order()
    s2 = (t2 + c * r) % group.order()
    print("Step 4: Responses 's1' and 's2' computed.")

    # 5. Assemble the final proof
    proof = {
        "T1": group_element_to_hex(T1),
        "T2": group_element_to_hex(T2),
        "c": c.hex(),
        "s1": s1.hex(),
        "s2": s2.hex()
    }
    
    print("Step 5: NIZK Proof generated successfully.")
    return proof

def verify_binding_proof(proof, P_patient_a, P_patient_b, pk_patient, patient_id_str):
    """
    Verifies the NIZK proof of binding.
    """
    print("\n--- Verifying NIZK Binding Proof (PTA's Side) ---")

    # Unpack the proof components
    T1 = hex_to_group_element(proof['T1'])
    T2 = hex_to_group_element(proof['T2'])
    c = Bn.from_hex(proof['c'])
    s1 = Bn.from_hex(proof['s1'])
    s2 = Bn.from_hex(proof['s2'])

    # Recompute Hash(PatientID)
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()
    
    # -- Verification Equation 1 (in GT, multiplicative) --
    print("Verifying Equation 1...")
    lhs1 = z ** s1
    patient_id_gt = z ** patient_id_fr
    p1_div_hash = P_patient_a * (patient_id_gt ** -1) 
    rhs1 = T1 * (p1_div_hash ** c)
    check1 = (lhs1 == rhs1)
    print(f"Verification Check 1 (in GT): {'PASSED' if check1 else 'FAILED'}")

    # -- Verification Equation 2 (in G2, additive) --
    print("Verifying Equation 2...")
    lhs2 = pk_patient * s2
    rhs2 = T2 + (P_patient_b * c)
    check2 = (lhs2 == rhs2)
    print(f"Verification Check 2 (in G2): {'PASSED' if check2 else 'FAILED'}")
    
    return check1 and check2



###
def schnorr_signature_generate(pseudonym_token_bytes, x_sign):
    """
    Generate a Schnorr signature using the finite field parameters.
    """
    r = 123456789  # Example fixed random nonce for testing
    R = pow(g1_schnorr, r, p1)  # Compute R = g^r mod p

    # Compute the challenge
    h = hashlib.sha256()
    h.update(R.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c = int.from_bytes(h.digest(), 'big') % q1

    # Compute the signature component s
    s = (r - c * x_sign) % q1

    return s, c  # Return signature (s, c)


def schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign):
    """
    Verify a Schnorr signature.
    """
    R_prime = (pow(g1_schnorr, s, p1) * pow(Y_sign, c, p1)) % p1  # R' = g^s * Y^c mod p

    # Compute the hash challenge
    h = hashlib.sha256()
    h.update(R_prime.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c_prime = int.from_bytes(h.digest(), 'big') % q1

    # Check if the computed c_prime matches the original c
    return c_prime == c


 #############################
# Main Function             #
#############################


iterations = 12
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


    patient_id = patient_credential['info']['patient_id']


    print("=== Generate Zero-Knowledge Proof ===")
    print(f"Hidden Attribute Indices and Values: {hidden_attribute_indices}")
    print(f"Disclosed Attribute Indices and Values: {disclosed_attribute_indices}\n")

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




    ###
    file_path = "/home/nmuslim162022/Desktop/mycode2/PT/patient_pseudonym_data.json"

    # Read JSON data from file    
    def read_json_file(file_path):
        with open(file_path, "r") as json_file:
            return json.load(json_file)
        

    # Serialization and Deserialization
    def group_element_to_hex(element):
        """Serialize a group element and convert it to a hex string."""
        return encode(element).hex()

    def hex_to_group_element(hex_str, group):
        """Deserialize a group element from a hex string."""
        element_bytes = bytes.fromhex(hex_str)
        return decode(element_bytes)   

    # --- Deserialization and Preparation for NIZK Proof ---

    # The hex_to_group_element function doesn't need the 'group' argument
    # because petlib's decode is smart enough.
    def hex_to_group_element(hex_str):
        """Deserialize a group element from a hex string."""
        element_bytes = bytes.fromhex(hex_str)
        return decode(element_bytes)





    pseudonym_data = read_json_file(file_path)
    print ("pseudonym_data: ", pseudonym_data)


    # Convert hex strings to cryptographic objects
    P_patient_a = hex_to_group_element(pseudonym_data['P_patient_a'])
    P_patient_b = hex_to_group_element(pseudonym_data['P_patient_b'])
    rk_patient_to_HRR = hex_to_group_element(pseudonym_data['rk_patient_to_HRR'])
    encrypted_pid = bytes.fromhex(pseudonym_data['encrypted_pid'])

    # THIS IS THE KEY FIX: Load the correct 'r' and convert it to a Bn object
    r_nizk = Bn.from_hex(pseudonym_data['r'])
    # Also load the matching public key and patient ID
    pk_patient_nizk = hex_to_group_element(pseudonym_data['pk_patient'])
    patient_id_nizk = pseudonym_data.get('patient_id', patient_id) # Use loaded ID for consistency

    # --- NIZK Proof Generation (Patient's Side) ---
    # The patient uses the loaded pseudonym and the CORRECT secret 'r' to generate the proof
    binding_proof = generate_binding_proof(
        P_patient_a, P_patient_b, r_nizk, pk_patient_nizk, patient_id_nizk
    )

    # Prepare the request to the APC server (appointment_token_id and proof_of_knowledge_verification_parameters) 
    data = {
        'pseudonym_data': pseudonym_data,
        'binding_proof': binding_proof,
        'proof_of_knowledge_patient_credential_verification_parameters': proof_of_knowledge_patient_id_verification_parameters
    }

    ##########################
    # processing by PTA
    ##########################

    # Verify the signature
    # #print("=== Verify Signature ===")
    try:
        signature_valid = verify_signature(signature, pk_issuer, credential_commitment, g2)
        # #print(f"Signature Valid: {signature_valid}")
    except Exception as e:
        print("Signature verification failed:", {e})
    

    if not signature_valid:
        print("Signature verification failed:", {e})

    print("=== ✨ ===")
    print ("c: ", c)
    print ("masked_sk_user: ", masked_sk_user)
    print ("masked_hidden: ", masked_hidden)
    print ("tilde_C: ", tilde_C)
    print ("H: ", H)
    print ("nonce: ", nonce)
    print ("C_hidden: ", C_hidden)
    print ("g1: ", g1)

    # Verify ZK proof
    print("=== Verify Zero-Knowledge Proof ===")
    zk_valid = verify_hidden_attribute_zk_proof(
            c, masked_sk_user, masked_hidden, tilde_C , H, nonce, C_hidden, g1
            )

    print(zk_valid)  


    print ("pseudonym_data: ", pseudonym_data)

    # Prepare the pseudonym token as a concatenated byte string for verification
    pseudonym_token_bytes = (
        bytes.fromhex(group_element_to_hex(P_patient_a)) +
        bytes.fromhex(group_element_to_hex(P_patient_b)) +
        bytes.fromhex(group_element_to_hex(rk_patient_to_HRR)) +
        bytes.fromhex(encrypted_pid.hex())
    )


    # --- NIZK Proof Verification (PTA's Side) ---
    # The PTA receives the pseudonym and the newly generated proof.
    # It MUST use the same public key and patient ID that were used in the proof generation.
    is_valid = verify_binding_proof(
        binding_proof, P_patient_a, P_patient_b, pk_patient_nizk, patient_id_nizk
    )
        
    print("\n--- Final Result ---")
    if is_valid:
        print("✅ The NIZK proof is VALID. The PTA can trust the binding between the pseudonym and the PatientID.")
    else:
        print("❌ The NIZK proof is INVALID. The request should be rejected.")


    # Generate Schnorr signature
    s, c = schnorr_signature_generate(pseudonym_token_bytes, x_sign)
    print("\nSignature generated:")
    print("s:", s)
    print("c:", c)
    print("Y_sign:", Y_sign)

    # Serialize and store data
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
            "Y_sign": Y_sign  # Directly convert Y_sign to hex since it's an integer
            }
        }


    # Save (optional)
    with open("/home/nmuslim162022/Desktop/mycode2/signed_pseudonym_token.json", "w") as f:
        json.dump(data_to_store, f, indent=2)

    # --- Example Verification ---
    valid = schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign)
    print("\nSignature valid:", valid)


    # Record the end time in nanoseconds
    end_time = time.perf_counter_ns()

    # Calculate the execution time in milliseconds
    execution_time_ms = (end_time - start_time) / 1_000_000
    #print(f"Execution time: {execution_time_ms} milliseconds")

    execution_times.append(execution_time_ms)

    time.sleep(5)


# Remove outliers and calculate stats
trimmed_times = execution_times[1:-1]
if trimmed_times:
    avg_time = np.mean(trimmed_times)
    std_dev = np.std(trimmed_times)
    print("Execution Times:", execution_times)
    print("Trimmed Execution Times:", trimmed_times)
    print(f"Average Execution Time: {avg_time:.2f} ms")
    print(f"Standard Deviation: {std_dev:.2f} ms") 