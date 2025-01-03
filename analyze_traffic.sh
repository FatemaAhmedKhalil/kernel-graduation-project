#!/bin/bash

# Bash Script to Analyze Network Traffic

# Input: Path to the Wireshark PCAP file
PCAP_FILE=$1  # capture input from terminal.
cd "$PCAP_FILE" || exit

# Function to extract information from the pcap file
analyze_traffic() {
    # Use tshark or similar commands for packet analysis.
    total_packets=$(tshark -r capture_file.pcap -T fields -e frame.number | wc -l) 

    # Hint: Consider commands to count total packets, filter by protocols (HTTP, HTTPS/TLS).
    http_packets=$(tshark -r capture_file.pcap -Y "http" -T fields -e frame.number | wc -l)
    https_packets=$(tshark -r capture_file.pcap -Y "tls" -T fields -e frame.number | wc -l)

    # extract IP addresses, and generate summary statistics.
    top_source_ips=$(tshark -r capture_file.pcap -T fields -e ip.src | sort | uniq -c | sort -nr | head -n 5) 
    top_dest_ips=$(tshark -r capture_file.pcap -T fields -e ip.dst | sort | uniq -c | sort -nr | head -n 5)
    
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
