import socket
import argparse
import os

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

def main():

    parser = argparse.ArgumentParser(description="Process file paths for filesys and bootstrap.")
    parser.add_argument('--filesys', type=str, required=True, help='Path to the file system ZIP file')
    parser.add_argument('--bootstrap', type=str, required=True, help='Path to the bootstrap ZIP file')
    parser.add_argument('--bin', type=str, required=False, help='Path to application device will boot')

    args = parser.parse_args()

    filesys_path = os.path.abspath(args.filesys)
    bootstrap_path = os.path.abspath(args.bootstrap)

    bin_path = None
    if args.bin:
        bin_path = os.path.abspath(args.bin)

    if not os.path.exists(filesys_path):
        print(f"filesys: {filesys_path} not found")
        return

    if not os.path.exists(bootstrap_path):
        print(f"bootstrap: {bootstrap_path} not found")
        return

    print(f"Filesys   Path: {filesys_path}")
    print(f"Bootstrap Path: {bootstrap_path}")
    print(f"bin       Path: {bin_path}")

    # Server configuration
    host = '0.0.0.0'   # Localhost
    port = 8080        # Port to listen on

    socket.setdefaulttimeout(5)
    # Create a socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
            server_socket.listen(2)  # Allow up to 2 connections
            hostname = socket.gethostname()
            server_ip = socket.gethostbyname(hostname)
            print(f"Server IP address: {server_ip}")
            print(f"Server is listening on {host}:{port}...")

            # Handle the first connection
            while True:
                # print("Waiting for first connection...")
                try:
                    conn1, addr1 = server_socket.accept()
                    with conn1:
                        print(f"Connected by {addr1}")

                        message = conn1.recv(1024).decode().strip().lower()
                        print(f"Received message: {message}")

                        if message == "filesys":
                            print("Sending file system")
                            send_file(conn1, filesys_path)
                        elif message == "bootstrap":
                            print("Sending bootstrap")
                            send_file(conn1, bootstrap_path)
                        elif message == "bin":
                            if bin_path:
                                print("Sending binary")
                                send_file(conn1, bin_path)
                            else:
                                print("No binary path provided, skipping binary send.")
                except TimeoutError:
                    continue
    except KeyboardInterrupt:
        print("\nkey int. exiting.")
        conn1.close()

if __name__ == "__main__":
        main()