# privacy_patient_script_patient_credential.py
# patient request patient credential from APC
import hashlib
from datetime import datetime
import sympy
from sympy import mod_inverse
import requests
import json
import time
import numpy as np



# Define the fixed patient credential information (6 attributes)
patient_info = {
    'name': 'John Smith',
    'social_security_number': '123-45-6789',
    'home_address': '123 Main St, Anytown, USA',
    'biometric_data': 'base64_encoded_image_data',
    'date_of_birth': '1990-01-01',
    'email': 'john.smith@example.com'  # Add this line
}

# APC for requesting the credential
apc_url = 'http://127.0.0.1:5000/request_patient_credential_signature'

##############################
#### define main function ####

# File paths
FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"

# Load the stored parameters
with open(FILE_PATH, 'r') as f:
    parameters = json.load(f)

pk_user = parameters['pk_user']
#print ("pk_user: ", pk_user)



data = {
        'patient_info': patient_info,
        'pk_user': pk_user,
}




iterations = 3
execution_times = []

for i in range(iterations):

    # Record the start time in nanoseconds
    start_time = time.perf_counter_ns()

    # user sends the data to the APC requesting the credential
    response = requests.post(apc_url, json=data)
    if response.status_code == 200: 
        try:
            patient_credential = response.json()  # Convert the list to a dictionary
            #print("Patient credential received 🍕:", patient_credential)

        
            # Write the dictionary to a JSON file
            with open(r'/home/nmuslim162022/Desktop/mycode2/patient_credential_signature.json', 'w') as json_file:
                json.dump(patient_credential, json_file, indent=4)


        except ValueError:
            print("Error: Response content is not valid JSON.")


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