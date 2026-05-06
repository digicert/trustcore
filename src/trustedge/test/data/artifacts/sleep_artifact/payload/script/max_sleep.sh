#!/bin/bash

# Initialize counter
counter=0

# Set the maximum number of iterations
if [ $# -eq 0 ]; then
    max_iterations=70
else
    # Check if the first argument is an integer
    if [[ "$1" =~ ^-?[0-9]+$ ]]; then
        max_iterations=$1
        echo "The argument is saved as an integer: $max_iterations"
    else
        max_iterations=70
    fi
fi

echo "iterations todo: $max_iterations"

# Loop with a counter
while [ $counter -lt $max_iterations ]
do
  # Your commands go here
  echo "Iteration $counter"

  # Sleep for 5 seconds
  sleep 5

  # Increment the counter
  counter=$((counter + 1))
done

echo "Loop has completed $max_iterations iterations."

