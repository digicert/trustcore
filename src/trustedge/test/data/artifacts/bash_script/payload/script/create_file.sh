#!/bin/bash

# Check if the user provided an output file
if [ -z "$1" ]; then
    echo "Usage: $0 <output_file>"
    exit 1
fi

# Check if the 'tree' command exists
if command -v tree &> /dev/null; then
    # Save the output of 'tree' into the specified file
    tree > "$1"
    echo "The output of 'tree' has been saved to $1"
else
    # Save the output of 'ls' into the specified file
    ls > "$1"
    echo "The output of 'ls' has been saved to $1"
fi

exit 0
