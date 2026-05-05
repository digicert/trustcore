from pathlib import Path
import argparse
import time
import csv
import shutil
from datetime import datetime

def handle_args():
    parser = argparse.ArgumentParser(description="Memory Stat Polling")

    parser.add_argument('--service-name', default="trustedge.service", type=str, help='name of service to monitor. Default: trustedge.service')
    parser.add_argument('--interval', type=int, default=5, help='time, in seconds, between polling memory stats. Default: 5')
    parser.add_argument('--out-csv-file', type=str, default="outfile.csv", help='file path for generated CSV file. Default: outfile.csv')

    return parser.parse_args()

def get_values(file_path):
    record = {}

    record["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            
            if line:
                key, value = line.split(maxsplit=1)
                record[key] = value
    
    return record

def write_to_csv(record, output_csv_path):
    file_exists = False
    keys = record.keys()

    if Path(output_csv_path).exists():
        file_exists = True

    with open(output_csv_path, mode='a', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=keys)

        if not file_exists:
            writer.writeheader()

        writer.writerow(record)
    
def main():
    tmp_stat_file = "memory.stat.tmp"
    
    args = handle_args()

    stat_file = f'/sys/fs/cgroup/system.slice/{args.service_name}/memory.stat'
    csv_file = args.out_csv_file

    print("Service monitoring:", args.service_name)
    print("CSV file:", csv_file)

    try:
        statsFile = Path(stat_file)
        while not statsFile.exists():
            print("Service not started..")
            time.sleep(3)

        Path(csv_file).unlink(csv_file)

        while statsFile.exists():
            shutil.copyfile(stat_file, tmp_stat_file)
            record = get_values(tmp_stat_file)
            write_to_csv(record, csv_file)

            print(f"time: {record['timestamp']}, anon: {record['anon']}, file: {record['file']}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nProgram interrupted.")
              
    print(" Exiting gracefully...")
    Path(tmp_stat_file).unlink(tmp_stat_file)

if __name__ == "__main__":
    main()