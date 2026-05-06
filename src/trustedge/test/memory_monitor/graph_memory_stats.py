import pandas as pd
import matplotlib.pyplot as plt
import paramiko
import os
from scp import SCPClient
import argparse

def process_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scp", help="Enable SCP for file", action="store_true")
    parser.add_argument("--username", type=str, help="user for remote server")
    parser.add_argument("--password", type=str, help="password of user")
    parser.add_argument("--ip", type=str, help="IP address of remote server")
    parser.add_argument("--port", type=int, default=22, help="port of remote server. default: 22")
    parser.add_argument("--file-path", type=str, default="outfile.csv", help="port of remote server. default: outfile.csv")

    args = parser.parse_args()
    print(f"file path: {args.file_path}")
    if (args.scp):
        print(f"user     : {args.username}")
        print(f"password : {args.password}")
        print(f"ip       : {args.ip}")
        print(f"port     : {args.port}")
    return args

def create_ssh_client(server, port, user, password):
    """Create an SSH client to connect to the server."""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, password)
    return client

def scp_file(remote_path, server, port, user, password):
    """Transfer a file using SCP."""
    try:
        ssh = create_ssh_client(server, port, user, password)
        with SCPClient(ssh.get_transport()) as scp:
            scp.get(remote_path)  # Download file
            print(f"File {remote_path} has been downloaded")
    except Exception as e:
        print(e)

args = process_arguments()

if args.scp:
    remote_path = args.file_path 
    print(f"remote path: {args.file_path}")
    scp_file(remote_path, args.ip, args.port,
            args.username, args.password)
    file_path = 'outfile.csv'
    print(f"filepath: {file_path}")
    file_size = os.path.getsize(file_path)
    print("done")
else:
    file_path = args.file_path 
    file_size = os.path.getsize(file_path)
print(f"file path: {file_path}")
print(f"file size: {file_size}")

data = pd.read_csv(file_path, parse_dates=['timestamp'])

data.set_index('timestamp', inplace=True)

available_columns = data.columns.tolist()
print("Available columns:", available_columns)

columns_to_plot = input("Enter the colum names to plot, separated by commas: ").split(',')
print(columns_to_plot)
print(len(columns_to_plot[0]))
print_all=False
if len(columns_to_plot[0]) > 0:
    columns_to_plot = [col.strip() for col in columns_to_plot]
    valid_columns = [col for col in columns_to_plot if col in available_columns]
else:
    print_all=True

if print_all:
    data.plot()
else:
    data[valid_columns].plot()

plt.xlabel("time")
plt.ylabel("values")
plt.title("memory stats over time")
plt.grid(True)
plt.show()
