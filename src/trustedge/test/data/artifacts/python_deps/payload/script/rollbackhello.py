#!/bin/python3

import sys

def main():
    # Print the script name
    script_name = sys.argv[0]
    print(f"script name: {script_name}")

    # Print the arguments
    arguments = sys.argv[1:]
    print("args:")
    for index, arg in enumerate(arguments):
        print(f"  {index + 1}: {arg}")

if __name__ == "__main__":
    main()

