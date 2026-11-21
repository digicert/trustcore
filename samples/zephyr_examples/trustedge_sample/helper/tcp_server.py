import socket
import argparse
import os
import requests
import json
import time
import tempfile

def send_file(conn, file_name):
    """Sends a file to the connected client."""
    try:
        with open(file_name, 'rb') as file:
            while chunk := file.read(1024):
                conn.sendall(chunk)
        print(f"{file_name} sent successfully.")
    except FileNotFoundError:
        print(f"Error: {file_name} not found.")
        conn.sendall(b"ERROR: File not found.")

def register_device_with_csr(server_url, api_key, account_id, device_group_id, certificate_policy_id, device_name, csr_pem):
    """
    Registers a device with a CSR using the Device Trust Manager API.
    Returns the device ID on success, None on failure.
    """
    payload = {
        "name": device_name,
        "description": device_name,
        "deviceGroupId": device_group_id,
        "accountId": account_id,
        "certificatePolicies": {
            "bootstrap": [
                {
                    "certificatePolicyId": certificate_policy_id,
                    "csr": csr_pem
                }
            ]
        }
    }

    headers = {
        'Content-Type': 'application/json',
        'x-api-key': api_key
    }

    url = f"{server_url}/api/v3/device/registration"
    print(f"Registering device '{device_name}' with CSR...")
    print(f"POST {url}")
    print(f"Headers: x-api-key={api_key[:8]}...") # Print partial key for debug
    print(f"CSR in payload ({len(csr_pem)} chars):")
    print(f"  First 80 chars: {repr(csr_pem[:80])}")
    print(f"  Last 80 chars: {repr(csr_pem[-80:])}")
    print(f"Full payload JSON:\n{json.dumps(payload, indent=2)}")

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.status_code == 200 or response.status_code == 201:
            print(f"Device '{device_name}' registered successfully.")
            return response.json()
        else:
            print(f"Device registration failed. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"Error during device registration: {e}")
        return None

def search_device(server_url, api_key, account_id, device_name):
    """
    Search for a device by name and return its ID.
    """
    headers = {
        'x-api-key': api_key
    }

    url = f"{server_url}/api/v3/device"
    params = {
        'name': device_name,
        'accountId': account_id
    }

    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code == 200:
            data = response.json()
            if data.get('records') and len(data['records']) > 0:
                return data['records'][0].get('id')
        print(f"Device not found: {device_name}")
        return None
    except Exception as e:
        print(f"Error searching for device: {e}")
        return None

def download_bootstrap_config(server_url, api_key, device_id, output_path):
    """
    Download the bootstrap configuration for a device.
    Returns True on success, False on failure.
    """
    headers = {
        'x-api-key': api_key
    }

    url = f"{server_url}/api/v3/bootstrap-config/download/{device_id}"
    max_retries = 5
    retry_interval = 2

    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == 200:
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                print(f"Bootstrap config downloaded to {output_path}")
                return True
            elif response.status_code == 404 or response.status_code == 429:
                print(f"Bootstrap not ready (HTTP {response.status_code}), retrying in {retry_interval}s... ({attempt+1}/{max_retries})")
                time.sleep(retry_interval)
            else:
                print(f"Failed to download bootstrap config. Status: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error downloading bootstrap config: {e}")
            return False

    print("Max retries reached for bootstrap download.")
    return False

def handle_bootstrapparams(conn, server_url, api_key, account_id, device_group_id, certificate_policy_id):
    """
    Handle the bootstrapparams request:
    1. Receive the device name from the client
    2. Receive the CSR from the client
    3. Register the device with the CSR
    4. Download and send the bootstrap config
    """
    # Receive the device name and CSR - follows immediately after "bootstrapparams"
    print("Waiting for device name and CSR data...")
    all_data = b""

    # Set a short timeout to detect end of data
    conn.settimeout(2.0)
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            all_data += chunk
            # Check if we've received the full PEM (ends with -----END CERTIFICATE REQUEST-----)
            if b"-----END CERTIFICATE REQUEST-----" in all_data:
                break
    except socket.timeout:
        pass  # Timeout is expected when data is fully received

    if not all_data:
        print("Error: No data received")
        conn.sendall(b"ERROR: No data received")
        return

    # Parse device name (first line) and CSR (rest)
    data_str = all_data.decode('utf-8', errors='ignore')
    lines = data_str.split('\n', 1)

    if len(lines) < 2:
        print("Error: Expected device name followed by CSR")
        conn.sendall(b"ERROR: Invalid data format")
        return

    device_name = lines[0].strip()
    csr_pem = lines[1].strip()

    print(f"Raw CSR before normalization ({len(csr_pem)} bytes): {repr(csr_pem[:100])}")

    # Normalize CRLF to LF (PEM from C code uses CRLF)
    csr_pem = csr_pem.replace('\r\n', '\n').replace('\r', '\n')

    print(f"CSR after normalization ({len(csr_pem)} bytes): {repr(csr_pem[:100])}")

    if not device_name:
        # Fallback to timestamp-based name if device name is empty
        device_name = f"device-{int(time.time())}"

    print(f"Device name: {device_name}")
    print(f"Received CSR ({len(csr_pem)} bytes)")

    # Debug: check format
    if csr_pem.startswith("-----BEGIN"):
        print("CSR is in PEM format")
        csr_lines = csr_pem.split('\n')
        print(f"CSR has {len(csr_lines)} lines")
    else:
        print(f"WARNING: CSR does not start with PEM header")
        print(f"First 50 chars: {repr(csr_pem[:50])}")

    # Register the device with the CSR
    result = register_device_with_csr(
        server_url, api_key, account_id, device_group_id,
        certificate_policy_id, device_name, csr_pem
    )

    if not result:
        print("Device registration failed")
        conn.sendall(b"ERROR: Device registration failed")
        return

    # Search for the device to get its ID
    print(f"Searching for device '{device_name}'...")
    device_id = search_device(server_url, api_key, account_id, device_name)

    if not device_id:
        print("Could not find registered device")
        conn.sendall(b"ERROR: Device not found after registration")
        return

    print(f"Found device ID: {device_id}")

    # Download the bootstrap config to a temp file
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
        tmp_path = tmp.name

    if download_bootstrap_config(server_url, api_key, device_id, tmp_path):
        # Send the bootstrap config to the client
        print("Sending bootstrap config to client...")
        send_file(conn, tmp_path)
        os.unlink(tmp_path)
    else:
        conn.sendall(b"ERROR: Failed to download bootstrap config")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

def main():

    parser = argparse.ArgumentParser(description="Process file paths for filesys and bootstrap.")
    parser.add_argument('--filesys', type=str, required=True, help='Path to the file system ZIP file')
    parser.add_argument('--bootstrap', type=str, required=False, help='Path to the bootstrap ZIP file (optional if using --server-url)')
    parser.add_argument('--bin', type=str, required=False, help='Path to application device will boot')

    # API configuration for bootstrapparams handling
    parser.add_argument('--server-url', type=str, required=False, help='Device Trust Manager server URL (e.g., https://one.digicert.com)')
    parser.add_argument('--api-key', type=str, required=False, help='API key for authentication')
    parser.add_argument('--account-id', type=str, required=False, help='Account ID')
    parser.add_argument('--device-group-id', type=str, required=False, help='Device Group ID')
    parser.add_argument('--certificate-policy-id', type=str, required=False, help='Certificate Policy ID')

    args = parser.parse_args()

    filesys_path = os.path.abspath(args.filesys)

    bootstrap_path = None
    if args.bootstrap:
        bootstrap_path = os.path.abspath(args.bootstrap)

    bin_path = None
    if args.bin:
        bin_path = os.path.abspath(args.bin)

    # Check if API config is provided for bootstrapparams support
    api_config_provided = all([args.server_url, args.api_key, args.account_id, args.device_group_id, args.certificate_policy_id])

    if not os.path.exists(filesys_path):
        print(f"filesys: {filesys_path} not found")
        return

    if bootstrap_path and not os.path.exists(bootstrap_path):
        print(f"bootstrap: {bootstrap_path} not found")
        return

    if not bootstrap_path and not api_config_provided:
        print("Error: Either --bootstrap or API configuration (--server-url, --api-key, --account-id, --device-group-id, --certificate-policy-id) must be provided")
        return

    print(f"Filesys   Path: {filesys_path}")
    print(f"Bootstrap Path: {bootstrap_path}")
    print(f"bin       Path: {bin_path}")
    if api_config_provided:
        print(f"API Config: server={args.server_url}, account={args.account_id}, group={args.device_group_id}")

    # Server configuration
    host = '0.0.0.0'   # Localhost
    port = 8080        # Port to listen on

    socket.setdefaulttimeout(5)
    # Create a socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
            server_socket.listen(2)  # Allow up to 2 connections
            print(f"Server is listening on {host}:{port}...")

            # Handle the first connection
            while True:
                # print("Waiting for first connection...")
                try:
                    conn1, addr1 = server_socket.accept()
                    with conn1:
                        print(f"Connected by {addr1}")

                        message = conn1.recv(1024).decode().strip()
                        print(f"Received message: {message}")
                        message_lower = message.lower()

                        if message_lower == "filesys":
                            print("Sending file system")
                            send_file(conn1, filesys_path)
                        elif message_lower == "bootstrapparams":
                            if api_config_provided:
                                print("Handling bootstrapparams request...")
                                handle_bootstrapparams(
                                    conn1,
                                    args.server_url,
                                    args.api_key,
                                    args.account_id,
                                    args.device_group_id,
                                    args.certificate_policy_id
                                )
                            else:
                                print("Error: API config not provided for bootstrapparams")
                                conn1.sendall(b"ERROR: Server not configured for bootstrapparams")
                        elif message_lower == "bootstrap":
                            print("Sending bootstrap")
                            if bootstrap_path:
                                send_file(conn1, bootstrap_path)
                            else:
                                print("Error: No bootstrap path provided")
                                conn1.sendall(b"ERROR: No bootstrap file configured")
                        elif message_lower == "bin":
                            if bin_path:
                                print("Sending binary")
                                send_file(conn1, bin_path)
                            else:
                                print("No binary path provided, skipping binary send.")
                except TimeoutError:
                    continue
    except KeyboardInterrupt:
        print("\nkey int. exiting.")

if __name__ == "__main__":
        main()