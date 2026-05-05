#!/usr/bin/bash

function notification_handler() {
    echo "-> Resource updated, please reload the certificate."
}

echo "Process with pid: $$ waiting for SIGUSR1..."
while true
do
    trap notification_handler SIGUSR1
    sleep 1
done
