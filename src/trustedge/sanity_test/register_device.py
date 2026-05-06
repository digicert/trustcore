import requests
import os
import platform
import sys
import time
import subprocess

url = 'https://demo.one.digicert.com/devicetrustmanager/api/v4/device/registration'

x_api_key = os.environ.get('DEMO_API_KEY')
if x_api_key is None:
    print("DEMO_API_KEY is not set")
    exit(1)
headers = {
    "x-api-key": x_api_key
}

# Use platform-specific device name and group
IS_WINDOWS = platform.system() == "Windows"
device_name = "Trustedge-Sanity-Test-Device-Final-Windows" if IS_WINDOWS else "Trustedge-Sanity-Test-Device-Final"
device_group_id = "89b599d6-1439-449f-a1c6-5b513710269a" if IS_WINDOWS else "9ecf6d49-2ba7-477d-a5e3-bdde1124c87e"

payload = {
    "name": device_name,
    "device_group_id": device_group_id,
    "account_id": "815af465-94ee-4a4b-b8c9-2a70b5e6f0bc",
    "certificate_policies": {
        "bootstrap": [
            {
                "certificate_policy_id": "IOT_353b088e-8a60-40f3-8ecf-71e7edf430b5",
                "server_side_key_gen": True,
                "key_type": "RSA_2048",
                "key_format": "PEM",
                "key_syntax": "PKCS8",
                "attributes": [
                    {
                        "name": "subject.common_name",
                        "value": "trustedge-sanity-test"
                    }
                ]
            }
        ]
    }
}

session = requests.Session()

# Retry registration up to 5 times
max_retries = 5
retryable_statuses = [403, 409, 500, 502, 503, 504]  # HTTP statuses that may be transient

for attempt in range(max_retries):
    try:
        reg_response = session.post(url, headers=headers, json=payload, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"Request failed with exception: {e}")
        if attempt < max_retries - 1:
            wait_time = 10 * (2 ** attempt)
            print(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
        else:
            print("Max retries reached. Exiting.")
            exit(1)
        continue

    if reg_response.status_code == 200:
        print("Registration successful")
        break
    elif reg_response.status_code in retryable_statuses and attempt < max_retries - 1:
        wait_time = 10 * (2 ** attempt)
        print(f"Attempt {attempt + 1} failed with status {reg_response.status_code}. Retrying in {wait_time} seconds...")
        time.sleep(wait_time)
    else:
        print("Registration failed")
        try:
            error_data = reg_response.json()
            print(f"Error details: {error_data}")
        except requests.exceptions.JSONDecodeError:
            error_data = None

        # Check if error is due to duplicate device name
        if error_data and error_data.get('error', {}).get('code') == '03':
            device_name = payload['name']
            print(f"Device name '{device_name}' already exists. Fetching device ID...")

            # Check if device exists
            device_url = 'https://demo.one.digicert.com/devicetrustmanager/api/v4/device'
            params = {
                "name": device_name,
                "device_group_id": device_group_id,
                "account_id": "815af465-94ee-4a4b-b8c9-2a70b5e6f0bc"
            }
            try:
                device_response = session.get(device_url, headers=headers, params=params, timeout=30)

                if device_response.status_code == 200:
                    device_data = device_response.json()
                    print(f"Device found: {device_data}")

                    # Extract device ID from response
                    records = device_data.get('records', [])
                    if not records:
                        print("Error: No device records found")
                        exit(1)

                    device_id = records[0].get('id')
                    if not device_id:
                        print("Error: Could not extract device ID from response")
                        exit(1)

                    print(f"Device ID: {device_id}")

                    # Get the directory where this script is located
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    delete_script = os.path.join(script_dir, 'disable_delete_device.py')

                    print("Running disable_delete_device.py...")
                    try:
                        result = subprocess.run(
                            ['python3', delete_script, device_id],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        print(result.stdout)
                        print("Device deleted. Please re-run registration.")
                        continue
                    except subprocess.CalledProcessError as e:
                        print(f"Failed to delete device: {e.stderr}")
                    except FileNotFoundError:
                        print(f"disable_delete_device.py not found at: {delete_script}")
                else:
                    print(f"Failed to fetch device details: {device_response.json()}")
            except requests.exceptions.RequestException as e:
                print(f"Failed to fetch device details: {e}")

        exit(1)

bootstrap_url = f'https://demo.one.digicert.com/devicetrustmanager/api/v4/bootstrap-config/download/{reg_response.json().get("device_id")}'
device_id = reg_response.json().get("device_id")
#save device id in a file
with open('device_id.txt', 'w') as f:
    f.write(device_id)

try:
    bootstrap_response = session.get(bootstrap_url, headers=headers, timeout=30)
    print(bootstrap_response.status_code)

    if (bootstrap_response.status_code == 200):
        zip_filename = "bootstrap.zip"
        with open(zip_filename, 'wb') as f:
            f.write(bootstrap_response.content)
        print(f"Bootstrap configuration downloaded successfully as {zip_filename}")
    else:
        print("Failed to download bootstrap configuration")
        print(bootstrap_response.json())
        exit(1)
except requests.exceptions.RequestException as e:
    print(f"Bootstrap download failed with exception: {e}")
    exit(1)
