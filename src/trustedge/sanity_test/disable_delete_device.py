import requests
import os
import sys
import time

x_api_key = os.environ.get('DEMO_API_KEY')
headers = {
    "x-api-key": x_api_key
}
value = sys.argv[1]

session = requests.Session()
max_retries = 5
disable_response = None
for attempt in range(max_retries):
    try:
        disable_url = f'https://demo.one.digicert.com/devicetrustmanager/api/v4/device/{value}/disable'
        body = {
            "reason": "No longer needed"
        }
        disable_response = session.patch(disable_url, headers=headers, json=body, timeout=30)
        if disable_response.status_code == 200:
            print("Disable successful")
            break
        else:
            print(f"Disable attempt {attempt + 1} failed with status {disable_response.status_code}")
            if attempt < max_retries - 1:
                wait_time = 10 * (2 ** attempt)
                time.sleep(wait_time)
    except requests.exceptions.RequestException as e:
        print(f"Disable request failed: {e}")
        if attempt < max_retries - 1:
            wait_time = 10 * (2 ** attempt)
            time.sleep(wait_time)
        else:
            print("Max retries reached for disable.")
            exit(1)

if disable_response is None or disable_response.status_code != 200:
    print("Disable failed after retries.")
    if disable_response is not None:
        try:
            print(disable_response.json())
        except requests.exceptions.JSONDecodeError:
            print("Failed")
    exit(1)

# Retry delete up to 5 times with exponential backoff, only if disable succeeded
delete_response = None
for attempt in range(max_retries):
    try:
        delete_url = f'https://demo.one.digicert.com/devicetrustmanager/api/v4/device/{value}/delete'
        delete_response = session.patch(delete_url, headers=headers, timeout=30)
        if delete_response.status_code == 200:
            print("Delete successful")
            break
        else:
            print(f"Delete attempt {attempt + 1} failed with status {delete_response.status_code}")
            if attempt < max_retries - 1:
                wait_time = 10 * (2 ** attempt)
                time.sleep(wait_time)
    except requests.exceptions.RequestException as e:
        print(f"Delete request failed: {e}")
        if attempt < max_retries - 1:
            wait_time = 10 * (2 ** attempt)
            time.sleep(wait_time)
        else:
            print("Max retries reached for delete.")
            exit(1)

if delete_response is None or delete_response.status_code != 200:
    print("Delete failed after retries.")
    if delete_response is not None:
        try:
            print(delete_response.json())
        except requests.exceptions.JSONDecodeError:
            print("Failed")
    exit(1)
