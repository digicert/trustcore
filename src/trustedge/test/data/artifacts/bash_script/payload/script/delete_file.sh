#!/bin/bash

# Check if the user provided an output file
if [ -z "$1" ]; then
    echo "Usage: $0 <output_file>"
    exit 1
fi

# Save the output of 'ls' into the specified file
if [ -f "$1" ]; then
    echo "File $1 exists. Deleting."
    rm -f "$1"
else
    echo "File $1 does not exist."
fi

exit 0
