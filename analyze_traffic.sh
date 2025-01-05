#!/bin/bash

# Bash Script to Analyze Network Traffic

# Input: Path to the Wireshark PCAP file
PCAP_FILE=$1  # Capture input from the terminal.

if [[ -f "$PCAP_FILE" ]]; then # Check if the input is a valid file
    # Get the absolute path of the file's directory
    FILE_DIR=$(dirname "$(realpath "$PCAP_FILE")") 
    cd "$FILE_DIR" || exit  # Change to the file directory

    # Extract the file extension and validate it
    file_extension=${PCAP_FILE##*.}
    if [[ "$file_extension" != "pcap" ]]; then
        echo "Error: '$PCAP_FILE' is not a valid PCAP file. Please provide a file with a .pcap extension."
        exit 1
    fi
else
    echo "Error: '$PCAP_FILE' is not a valid file. Please provide a valid PCAP file path."
    exit 1
fi


# Function to extract information from the pcap file
analyze_traffic() {
    # Use tshark or similar commands for packet analysis.
    total_packets=$(tshark -r "$PCAP_FILE" -T fields -e frame.number | wc -l) 

    # Hint: Consider commands to count total packets, filter by protocols (HTTP, HTTPS/TLS).
    http_packets=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e frame.number | wc -l)
    https_packets=$(tshark -r "$PCAP_FILE" -Y "tls" -T fields -e frame.number | wc -l)

    # extract IP addresses, and generate summary statistics.
    top_source_ips=$(tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | head -n 5) 
    top_dest_ips=$(tshark -r "$PCAP_FILE" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -n 5)
    
    # Output analysis summary
    echo "----- Network Traffic Analysis Report -----"
    # Provide summary information based on your analysis
    # Hints: Total packets, protocols, top source, and destination IP addresses.
    echo "1. Total Packets: $total_packets"
    echo "2. Protocols:"
    echo "   - HTTP: $http_packets packets"
    echo "   - HTTPS/TLS: $https_packets packets"
    echo ""
    echo "3. Top 5 Source IP Addresses:"
    # Provide the top source IP addresses
    echo "$top_source_ips"
    echo ""
    echo "4. Top 5 Destination IP Addresses:"
    # Provide the top destination IP addresses
    echo "$top_dest_ips"
    echo ""
    echo "----- End of Report -----"
}

# Run the analysis function
analyze_traffic
