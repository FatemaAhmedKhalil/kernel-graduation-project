#!/bin/bash

# Bash Script to Analyze Network Traffic

# Input: Path to the Wireshark PCAP file
PCAP_FILE=$1  # Capture input from the terminal.
if [[ -f "$PCAP_FILE" ]]; then
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

    # Count packets by protocol
    http_packets=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e frame.number | wc -l)
    https_packets=$(tshark -r "$PCAP_FILE" -Y "tls" -T fields -e frame.number | wc -l)

    # Extract IP addresses and generate summary statistics
    top_source_ips=$(tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | head -n 5) 
    top_dest_ips=$(tshark -r "$PCAP_FILE" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -n 5)
    
    # Output analysis summary
    echo "----- Network Traffic Analysis Report -----"
    echo "1. Total Packets: $total_packets"
    echo "2. Protocols:"
    echo "   - HTTP: $http_packets packets"
    echo "   - HTTPS/TLS: $https_packets packets"
    echo ""
    echo "3. Top 5 Source IP Addresses:"
    echo "$top_source_ips"
    echo ""
    echo "4. Top 5 Destination IP Addresses:"
    echo "$top_dest_ips"
    echo "----- End of Report -----"
}

# Run the analysis function
analyze_traffic
