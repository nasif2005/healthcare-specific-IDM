# APC.py
# This script implements the Application Processing Center (APC) functionality

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
import json
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import base64
import hashlib
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# Paths to the PEM private and public key files
private_key_path = r"/home/nmuslim162022/Desktop/mycode_RSA/apc_private_key.pem"
public_key_path = r"/home/nmuslim162022/Desktop/mycode_RSA/apc_public_key.pem"
apc_did = "did:example:apc123"  # DID of the APC
patient_did = "did:example:patient123"  # DID of the patient

# Auditor's endpoint URL
auditor_url = 'http://127.0.0.1:9000/store_APC_event'

app = Flask(__name__)

# MySQL Database configuration for the Auditor
db_config = {
    'host': '192.168.0.104',
    'user': 'myadmin1',
    'password': 'mypassword1',
    'database': 'myhealthcareservicedatabase1',
}

# Function to connect to the MySQL database
def connect_db():
    try:
        return mysql.connector.connect(**db_config)
    except Error as e:
        return None

# Load the private key from the PEM file
def load_private_key(private_key_path):
    try:
        with open(private_key_path, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,  # Add password here if the key is encrypted
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        raise

# Load the public key from the PEM file
def load_public_key(public_key_path):
    try:
        with open(public_key_path, "rb") as file:
            public_key = serialization.load_pem_public_key(
                file.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        raise

def generate_rsa_signature(patient_credential):
    """Sign a patient credential using raw RSA operations."""
    private_key = load_private_key(private_key_path)

    # Serialize the patient credential to a JSON string with sorted keys
    credential_bytes = json.dumps(patient_credential['info'], sort_keys=True).encode("utf-8")
    
    # Compute MD5 digest and truncate to first 8 bytes (64 bits)
    full_digest = hashlib.md5(credential_bytes).digest()
    digest = full_digest[:8]

    # Retrieve the private key numbers
    private_numbers = private_key.private_numbers()
    d = private_numbers.d  # Private exponent
    n = private_numbers.public_numbers.n  # Modulus

    # Convert the digest to an integer
    digest_int = int.from_bytes(digest, byteorder='big')
    
    # Ensure that digest_int is less than n
    if digest_int >= n:
        raise ValueError("Digest is too large for the key size.")
    
    # Perform RSA signing: s = digest^d mod n
    signature = pow(digest_int, d, n)
    
    # Convert the signature to bytes, ensuring fixed length
    signature_bytes = signature.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    return signature_bytes

def verify_rsa_signature(patient_credential, signature):
    """Verify a patient credential using raw RSA operations."""
    public_key = load_public_key(public_key_path)

    # Serialize the patient credential to a JSON string with sorted keys
    credential_bytes = json.dumps(patient_credential['info'], sort_keys=True).encode("utf-8")
    
    # Compute MD5 digest and truncate to first 8 bytes (64 bits)
    full_digest = hashlib.md5(credential_bytes).digest()
    digest = full_digest[:8]

    # Retrieve the public key numbers
    public_numbers = public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n

    # Convert the signature to an integer
    signature_int = int.from_bytes(signature, byteorder='big')
    
    # Perform RSA verification: verified_digest = s^e mod n
    verified_digest_int = pow(signature_int, e, n)
    
    # Convert the verified digest back to bytes, ensuring fixed length
    verified_digest = verified_digest_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    
    # Since we truncated the digest to 8 bytes, extract the last 8 bytes of the verified digest
    verified_digest = verified_digest[-8:]

    # Compare the verified digest with the original digest
    return verified_digest == digest

@app.route('/generate_patient_credential', methods=['POST'])
def generate_patient_credential():
    patient_info = request.get_json()

    # Simulate the verification process
    result = verify_patient_info()

    if result:
        # Simulate storing patient info and returning a patient ID
        '''
        patient_id = store_patient_info(patient_info)

        if patient_id is None:
            return jsonify({"error": "Failed to store patient information"}), 500
        '''

        # Since the above is commented out, define a dummy patient_id for now
        patient_id = "PT-0001"

        # Generate the patient credential
        patient_credential = {
            "info": {
                'credential_id': 'SN-0001',
                'did_patient': patient_did,
                'patient_id': "PT-0001",
                'biometric_data': patient_info['biometric_data'],
                'issue_date': datetime.now().strftime("%Y-%m-%d"),
                'did_apc': apc_did,
            },
        }

        # Generate the RSA signature
        signature = generate_rsa_signature(patient_credential)

        # Convert the signature to a Base64-encoded string
        signature_base64 = base64.b64encode(signature).decode('utf-8')

        # Add the Base64-encoded signature to the credential
        patient_credential['signature'] = signature_base64
         
        # Send event to Auditor
        auditor_data = {
            'patient_id': patient_id,
            'event_type': 'patient_credential_issued',
            'event_date': patient_credential['info']['issue_date'],
            'description': 'Patient credential generated by APC'
        }
        
        '''
        try:
            response = requests.post(auditor_url, json=auditor_data)
        except requests.exceptions.RequestException as err:
            print("APC - Error sending data to Auditor:", err)
        '''

        return jsonify(patient_credential), 200
    else:
        return jsonify({"error": "Invalid patient_info"}), 400

def store_patient_info(patient_info):
    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM APC_patient_info WHERE social_security_number = %s", (patient_info['social_security_number'],))
        existing_patient = cursor.fetchone()

        if existing_patient:
            patient_id = existing_patient['patient_id']
        else:
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

        return patient_id

    except Error as e:
        return None
    finally:
        if 'cursor' in locals() and cursor is not None:
            cursor.close()
        if 'connection' in locals() and connection.is_connected():
            connection.close()

# Dummy function for patient info verification
def verify_patient_info():
    return True

@app.route('/verify_patient_id', methods=['POST'])
def verify_patient_id_endpoint():
    data = request.get_json()
    patient_id = data.get("patient_id")
    
    result = verify_patient_id(patient_id)
    if result:
        return jsonify({"message": "Patient ID verified successfully"}), 200
    else:
        return jsonify({"error": "Invalid patient_id"}), 400

def verify_patient_id(patient_id):
    connection = connect_db()
    if connection is None:
        return False

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM APC_patient_info WHERE patient_id = %s", (patient_id,))
        result = cursor.fetchone()
        
        return result is not None  # Returns True if patient exists, otherwise False

    except Error as e:
        return False

    finally:
        if 'cursor' in locals() and cursor is not None:
            cursor.close()
        if 'connection' in locals() and connection.is_connected():
            connection.close()

@app.route('/verify_patient_credential', methods=['POST'])
def verify_patient_credential():
    patient_credential = request.get_json()

    # Extract the Base64-encoded signature from the JSON
    signature_base64 = patient_credential['signature']

    # Decode the Base64-encoded signature back to bytes
    signature_bytes = base64.b64decode(signature_base64)

    # Verify the patient credential signature
    result = verify_rsa_signature(patient_credential, signature_bytes)

    if result:
        return jsonify({"message": True}), 200
    else:
        return jsonify({"message": False}), 400

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)