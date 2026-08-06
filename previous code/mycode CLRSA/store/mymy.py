import json
import hashlib

# Generate of proof of knowledge of the user' patient id of the patient credential
# File path of the JSON file
file_path = r"/home/nmuslim162022/Desktop/mycode/patient_pseudonym_data.json"

# Load the JSON file
with open(file_path, 'r') as file:
    patient_pseudonym_data = json.load(file)

 
P_patient_a = patient_pseudonym_data['P_patient_a']
P_patient_b = patient_pseudonym_data['P_patient_b']
rk_patient_to_HRR = patient_pseudonym_data['rk_patient_to_HRR']
encrypted_pid =  patient_pseudonym_data['encrypted_pid']


print ("P_patient_a: ", P_patient_a)
print ("P_patient_b: ", P_patient_b)
print ("rk_patient_to_HRR: ", rk_patient_to_HRR)
print ("encrypted_pid: ", encrypted_pid)


file_path = r"/home/nmuslim162022/Desktop/mycode/AT_credential_signature.json"

# Load the JSON file
with open(file_path, 'r') as file:
    AT = json.load(file)

print ("AT_credential: ", AT)


# === Assemble the payload object ===
# This is the first part of the tuple in the document's definition.
payload_data = {
    "Ppatient": [P_patient_a, P_patient_b],
    "rkpatient_to_HRR": rk_patient_to_HRR,
    "ctPID": encrypted_pid,
    "AT": AT,
    "ScheduleInfo": "schedule_info"
}

# It's crucial to serialize in a consistent way (sorted keys) so the signature is always verifiable.
# The result must be bytes.
serialized_payload = json.dumps(payload_data, sort_keys=True, separators=(',', ':')).encode('utf-8')

# Typically, you sign the HASH of the data, not the raw data itself.
payload_hash = hashlib.sha256(serialized_payload).digest()



print ("payload_hash: ", payload_hash)