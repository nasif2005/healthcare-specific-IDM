# APC process AT.py
from flask import Flask, request, jsonify
from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.pack import encode, decode
from petlib.bn import Bn
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from petlib.bn import Bn
import json
import logging
import mysql.connector
from mysql.connector import Error
import hashlib
from datetime import date
import requests
from datetime import datetime


# File paths
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"


# Auditor URL
auditor_url = 'http://127.0.0.1:9000/hrr_access_event'


# Initialize pairing group
group = BpGroup()
p = group.order()


# Flask app
app = Flask(__name__)


# Database configuration for the healthcare organization
db_config = {
    'host': '192.168.0.104',
    'user': 'myadmin3',
    'password': 'mypassword3',
    'database': 'myhealthcareservicedatabase3'
}


# Helper function: Connect to the database
def connect_db():
    try:
        connection = mysql.connector.connect(**db_config)  # Unpack the db_config dictionary
        return connection
    except Error as e:
        logging.error(f"Database connection error: {e}")
        return None


def verify_signature(signature, pk_issuer, credential_commitment, g2):
    """Verify the signature using pairing operations."""
    return group.pair(signature, g2) == group.pair(credential_commitment, pk_issuer)


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
    # #print(f"Term1: {term1}")
    # #print(f"Term2: {term2}")
    # #print(f"cC: {cC}")
    # #print(f"Recomputed Tilde_C: {tilde_C_prime}")

    # Step 3: Validate the proof
    is_valid = c == c_prime
    # #print(f" Zero-Knowledge Proof Valid: {is_valid}")
    return is_valid

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


def serialize_g1elem(obj):
    if isinstance(obj, G1Elem):  # Use the imported G1Elem directly
        return obj.export().hex()  # Serialize as a hex string
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


# Serialization and Deserialization
def group_element_to_hex(element):
    """Serialize a group element and convert it to a hex string."""
    return encode(element).hex()


def hex_to_group_element(hex_str, group):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)


def compute_commitment_for_expiration_date(H_expiration, expiration_date):
    """Compute the commitment for the expiration date."""
    # Hash and reduce the expiration_date
    value_expiration = hash_and_reduce(expiration_date, p)

    # Compute the commitment
    commitment_expiration = H_expiration.mul(value_expiration)
    return commitment_expiration


def generate_signature(issuer_sk, credential_commitment):
    """Generate a signature using the issuer's private key."""
    return credential_commitment.mul(issuer_sk)


def verify_signature(signature, pk_issuer, credential_commitment, g2):
    """Verify the signature using pairing operations."""
    return group.pair(signature, g2) == group.pair(credential_commitment, pk_issuer)


def hash_and_reduce(attribute, n):
    """Hash an attribute and reduce modulo n."""
    attribute_hash = hashlib.sha256(attribute.encode()).hexdigest()
    attribute_bn = Bn.from_hex(attribute_hash)  # Safely handle large hash values
    return attribute_bn % n


def verify_zk_proof_for_appointment_and_key(proof):
    """
    Verify the ZKP proving knowledge of sk_user and appointment_token_id.
    """

   # Load additional parameters
    parameters = read_json_file(PARAMETERS_FILE_PATH)
    H = [decode(bytes.fromhex(h)) for h in parameters['H']]
    g1 = decode(bytes.fromhex(parameters['g1']))

    
    r = group.order()


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


@app.route('/request_AT_credential_signature', methods=['POST'])
def request_AT_credential_signature():
    data = request.get_json()  # Extract JSON data from the request
    # #print("Data: ", data)

    zk_proof_appointment_token_id_attribute = data ['zk_proof_appointment_token_id_attribute']
    zk_proof_appointment_token_id_attribute = decode(bytes.fromhex(zk_proof_appointment_token_id_attribute)) 
    #print ( decode(bytes.fromhex(zk_proof_appointment_token_id_attribute)) )
    #print ("zk_proof_appointment_token_id_attribute: ", zk_proof_appointment_token_id_attribute)
    # Verify ZKP
    is_valid = verify_zk_proof_for_appointment_and_key(zk_proof_appointment_token_id_attribute)
    print(f"ZKP valid *: {is_valid}")

    H_appointment_token_id = zk_proof_appointment_token_id_attribute['H_appointment_token_id']
    print ("zk_proof_appointment_token_id_attribute: ", zk_proof_appointment_token_id_attribute['H_appointment_token_id'])

    # #print ("Commitment Appointment Token ID: ", commitment_appointment_token_id)
    #commitment_appointment_token_id = encode(commitment_appointment_token_id).hex()
    # #print ("Commitment Appointment Token ID 😊: ", commitment_appointment_token_id)

    # Deserialize fields
    signature = decode(bytes.fromhex(data['proof_of_knowledge_patient_id_verification_parameters']['signature']))  # Decode hex to bytes, then to G1Elem
    credential_commitment = decode(bytes.fromhex(data['proof_of_knowledge_patient_id_verification_parameters']['credential_commitment']))  # Decode hex to G1Elem

    c = Bn.from_hex(data['proof_of_knowledge_patient_id_verification_parameters']['c'])  # Deserialize hex to Bn
    masked_sk_user = Bn.from_hex(data['proof_of_knowledge_patient_id_verification_parameters']['masked_sk_user'])  # Deserialize hex to Bn
    masked_hidden = {int(k): Bn.from_hex(v) for k, v in data['proof_of_knowledge_patient_id_verification_parameters']['masked_hidden'].items()}  # Deserialize each Bn
    tilde_C = decode(bytes.fromhex(data['proof_of_knowledge_patient_id_verification_parameters']['tilde_C']))  # Deserialize hex to G1Elem
    H = [decode(bytes.fromhex(h)) for h in data['proof_of_knowledge_patient_id_verification_parameters']['H']]  # Deserialize list of G1Elem
    nonce = Bn.from_hex(data['proof_of_knowledge_patient_id_verification_parameters']['nonce'])  # Deserialize hex to Bn
    C_hidden = decode(bytes.fromhex(data['proof_of_knowledge_patient_id_verification_parameters']['C_hidden']))  # Deserialize hex to G1Elem
    
    patient_id = data['proof_of_knowledge_patient_id_verification_parameters']['disclosed_attributes']  # Leave as-is

    # #print("Deserialized Data:")
    # #print("Signature:", signature)
    # #print("Credential Commitment:", credential_commitment)
    # #print("Challenge (c):", c)
    # #print("Masked sk_user:", masked_sk_user)
    # #print("Masked Hidden:", masked_hidden)
    # #print("Tilde_C:", tilde_C)
    # #print("disclosed_attributes (patient_id): ", patient_id)

    # Load additional parameters
    parameters = read_json_file(PARAMETERS_FILE_PATH)
    g1 = decode(bytes.fromhex(parameters['g1']))
    g2 = decode(bytes.fromhex(parameters['g2']))
    pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
    sk_issuer = Bn.from_hex(parameters['sk_issuer'])

    # Verify the signature
    # #print("=== Verify Signature ===")
    try:
        signature_valid = verify_signature(signature, pk_issuer, credential_commitment, g2)
        # #print(f"Signature Valid: {signature_valid}")
    except Exception as e:
        # #print(f"Signature Verification Error: {e}")
        return jsonify({'error': f'Signature verification failed: {e}'}), 500

    if not signature_valid:
        return jsonify({'error': 'Invalid signature'}), 403

    # #print("=== ✨ ===")
    # #print ("c: ", c)
    # #print ("masked_sk_user: ", masked_sk_user)
    # #print ("masked_hidden: ", masked_hidden)
    # #print ("tilde_C: ", tilde_C)
    # #print ("H: ", H)
    # #print ("nonce: ", nonce)
    # #print ("C_hidden: ", C_hidden)
    # #print ("g1: ", g1)

    # Verify ZK proof
    # #print("=== Verify Zero-Knowledge Proof ===")
    zk_valid = verify_hidden_attribute_zk_proof(
            c, masked_sk_user, masked_hidden, tilde_C , H, nonce, C_hidden, g1
        )

    # 
    expiration_date = date.today().strftime("%Y-%m-%d")
    commitment_expiration_date = compute_commitment_for_expiration_date(H[1], expiration_date)

    # Combine commitments
    aggregate_commitment = group.gen1().add(H_appointment_token_id).add(commitment_expiration_date)

    # Generate signature
    signature = generate_signature(sk_issuer, aggregate_commitment)
    signature_hex = signature.export().hex()
    # #print("Signature (hex):", signature_hex)

    # Verify signature
    if verify_signature(signature, pk_issuer, aggregate_commitment, g2):
        # #print("Signature verification succeeded.")
        #result = "Signature verification succeeded."
        pass
    else:
        # #print("Signature verification failed.")
        #result = "Signature verification failed."
        pass

    # Construct the credential with signature
    AT_credential = {
        'info': {
            "appointment_token_id": None,
            'expiration_date': expiration_date
        },
        'signature': serialize_g1elem(signature)  # Serialize the G1Elem object
    }
    # #print ("AT_credential: ", AT_credential)


    # Send pseudonym event to the Auditor
    auditor_data = {
            'requester_id': patient_id,
            'event_type': 'Patient Request',
            'event_date': datetime.now().strftime("%Y-%m-%d"),
            'description': f"patient with ID {patient_id} access health record"
    }

    '''
    try:
        response = requests.post(auditor_url, json=auditor_data)
        if response.status_code == 200:
            # #print("Event successfully sent to the Auditor.")
            pass
        else:
            # #print("Failed to send event to Auditor:", response.text)
            pass

    except requests.exceptions.RequestException as err:
            # #print("Error sending event to Auditor:", err)
            pass
    '''        
    
    return jsonify(AT_credential), 200


# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)