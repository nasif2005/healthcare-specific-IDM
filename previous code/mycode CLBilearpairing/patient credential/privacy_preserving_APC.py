from flask import Flask, request, Response, jsonify
from bplib.bp import BpGroup
from petlib.pack import encode, decode
from petlib.bn import Bn
import json
import requests
import mysql.connector
from mysql.connector import Error
from collections import OrderedDict
from datetime import datetime
import hashlib

# Auditor's endpoint URL
auditor_url = 'http://127.0.0.1:9000/store_patient_event'

# Initialize pairing group (using BN254 by default in bplib)
group = BpGroup()
p = group.order()  # Prime order of the group

# Database configuration for APC
db_config = {
    'host': '192.168.0.104',
    'user': 'myadmin3',
    'password': 'mypassword3',
    'database': 'myhealthcareservicedatabase3'
}

# --- Public Parameters Setup ---
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']

apc_did = "did:example:apc123"  # DID of the APC
patient_did = "did:example:patient123"  # DID of the patient


app = Flask(__name__)

# Helper function to connect to the database
def connect_db():
    try:
        return mysql.connector.connect(**db_config)
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None


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


# Function to store or retrieve patient info in the APC_patient_info table
def store_patient_info(patient_info):
    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)
        
        # Check if patient already exists based on SSN
        cursor.execute("SELECT * FROM APC_patient_info WHERE social_security_number = %s", (patient_info['social_security_number'],))
        existing_patient = cursor.fetchone()

        if existing_patient:
            #print("Patient already exists with ID:", existing_patient['patient_id'])
            patient_id = existing_patient['patient_id']
        else:
            # Insert new patient record into APC_patient_info
            query = """
                INSERT INTO APC_patient_info (name, social_security_number, home_address, biometric_data, date_of_birth, email)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (
                patient_info['name'],
                patient_info['social_security_number'],
                patient_info['home_address'],
                patient_info['biometric_data'],
                patient_info['date_of_birth'],
                patient_info['email']
            ))
            connection.commit()
            patient_id = cursor.lastrowid
            #print("New patient stored with ID:", patient_id)

        return patient_id

    except Error as e:
        print("Error while accessing the database:", e)
        return None
    finally:
        if 'cursor' in locals() and cursor is not None:
            cursor.close()
        if 'connection' in locals() and connection.is_connected():
            connection.close()


# Endpoint to generate CL signature
@app.route('/request_patient_credential_signature', methods=['POST'])
def generate_credential_signature():
    data = request.json
    #print("Received from patient: ", data['patient_info'])
    patient_info = data['patient_info']
    pk_user = decode(bytes.fromhex(data['pk_user']))

    # Load the public key components
    FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"
    with open(FILE_PATH, 'r') as f:
        parameters = json.load(f)

    g1 = decode(bytes.fromhex(parameters['g1']))
    g2 = decode(bytes.fromhex(parameters['g2']))
    H = [decode(bytes.fromhex(h)) for h in parameters['H']]
    sk_issuer = Bn.from_hex(parameters['sk_issuer'])
    pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))

    # Validate required patient info fields
    required_fields = ['name', 'social_security_number', 'home_address', 'biometric_data', 'date_of_birth', 'email']
    for field in required_fields:
        if field not in patient_info:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Store patient information in the database and retrieve patient_id
    # patient_id = store_patient_info(patient_info)
    patient_id = "PT-0001"
    if patient_id is None:
        return jsonify({"error": "Failed to store patient information"}), 500

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

    #print("Patient credential at APC (initial):", patient_credential)

    # Generate attribute values based on ATTRIBUTE_ORDER
    attribute_values = [
        hash_and_reduce(str(patient_credential['info'][attr]), p) for attr in ATTRIBUTE_ORDER
    ]

    # Compute commitments and generate signature
    aggregate_commitment = compute_aggregate_commitment(H, attribute_values)
    credential_commitment = credential_commitment_func(pk_user, aggregate_commitment)
    signature = generate_signature(sk_issuer, credential_commitment)

    '''
    if verify_signature(signature, pk_issuer, credential_commitment, g2):
        print("Signature is valid.")
    else:
        print("Signature verification failed.")
    '''    

    # Serialize and return patient credential
    patient_credential['signature'] = encode(signature).hex()
    patient_credential_json = json.dumps(patient_credential, indent=4)
    #print("Patient credential at APC (ordered):", patient_credential_json)



    return Response(patient_credential_json, content_type="application/json")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
