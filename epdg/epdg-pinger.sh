#!/bin/bash

# Check if the file containing FQDNs is provided as an argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <file_containing_fqdns>"
    exit 1
fi

# Check if the file exists
if [ ! -f "$1" ]; then
    echo "Error: File '$1' not found."
    exit 1
fi

# Read FQDNs from the file and execute ping for each of them
while IFS= read -r fqdn; do
    echo "Pinging $fqdn ..."
    ping -c 1 -W 0.3 "$fqdn" | grep -E 'epdg.*bytes|bytes.*epdg'
    #echo "--------------------------------------"
done < "$1"
