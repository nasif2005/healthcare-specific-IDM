#  
# This script sends a request to the APC (Automated Patient Credentialing) service
# to generate a patient credential based on provided patient information.
import requests
import json
from Crypto.PublicKey import RSA
import time
import numpy as np
import base64
import os

# API endpoint of APC
APC_url = 'http://127.0.0.1:5000/generate_patient_credential'



# Path to the PEM public key file
public_key_path = r"/home/nmuslim162022/Desktop/mycode_RSA/apc_public_key.pem"

patient_info = {
    'name': 'John Smith',
    'social_security_number': '123-45-6789',
    'home_address': '123 Main St, Anytown, USA',
    'biometric_data': 'base64_encoded_image_data',
    'date_of_birth': '1990-01-01',
    'email': 'john.smith@example.com'
}

# Load the public key from the PEM file
def load_public_key():
    try:
        with open(public_key_path, "rb") as file:
            public_key = RSA.import_key(file.read())
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        raise

# Execution time measurement arrays
execution_times = []

# Main loop for multiple measurements
num_iterations = 12  # Adjust the number of iterations
for i in range(num_iterations):
    # Record the start time in nanoseconds
    start_time = time.perf_counter_ns()

    try:
        # Send request to APC
        response = requests.post(APC_url, json=patient_info)
        if response.status_code == 200:
            patient_credential = response.json()
            #print(f"Iteration {i + 1}: Patient credential received successfully.")
        
    except requests.exceptions.RequestException as e:
        print(f"Iteration {i + 1}: Connection error: {e}")
    except Exception as e:
        print(f"Iteration {i + 1}: An unexpected error occurred: {e}")

    # Record the end time in nanoseconds
    end_time = time.perf_counter_ns()

    # Calculate and store execution time in milliseconds
    execution_time_ms = (end_time - start_time) / 1_000_000
    execution_times.append(execution_time_ms)

    time.sleep(1) # Delay between iterations

# Trim first and last measurements to reduce noise
trimmed_execution_times = execution_times[1:-1]

# Calculate average and standard deviation of trimmed times
average_time = np.mean(trimmed_execution_times)
std_deviation = np.std(trimmed_execution_times)

# Print results
print("Execution Times:", execution_times)
print("Trimmed Execution Times:", trimmed_execution_times)
print(f"Average Execution Time: {average_time:.2f} ms")
print(f"Standard Deviation: {std_deviation:.2f} ms")



print (f"Patient Credential: {json.dumps(patient_credential, indent=4)}")

# Define output path for the JSON file
output_dir = r"/home/nmuslim162022/Desktop/mycode_RSA/"
output_filename = "patient_credential.json"
output_path = os.path.join(output_dir, output_filename)

# Save the patient credential as JSON
with open(output_path, "w", encoding="utf-8") as outfile:
    json.dump(patient_credential, outfile, indent=4)

print(f"Patient credential saved to: {output_path}")

