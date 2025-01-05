#!/bin/bash

# Bash Script to Analyze Network Traffic

# Input: Path to the Wireshark PCAP file
PCAP_FILE=$1  # Capture input from the terminal.
if [[ -f "$PCAP_FILE" ]]; then # Check if the input is a valid file 

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
    echo "----- End of Report -
----"
}

# Run the analysis function
analyze_traffic

ChatGPT said:
ChatGPT
In this script, FILE_DIR is assigned the directory path of the provided PCAP file using:

bash
Copy code
FILE_DIR=$(dirname "$(realpath "$PCAP_FILE")")
However, FILE_DIR is not used anywhere else in the script. It was likely added for debugging, storing logs, or specifying an output location in an earlier version of the script.

Can you remove it?
Yes, you can safely remove FILE_DIR from the script without affecting its functionality, as long as there is no intention to use it in the future. The updated script would look like this:

bash
Copy code
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
This makes the script cleaner and avoids unnecessary variables.






You said:
Does it check the existing file any where ?
ChatGPT said:
ChatGPT
Yes, your script checks if the provided file exists at the beginning of the script with the following condition:

bash
Copy code
if [[ -f "$PCAP_FILE" ]]; then
This checks whether the file specified by the user exists and is a regular file. If the file does not exist or is invalid, the script executes the else block:

bash
Copy code
else
    echo "Error: '$PCAP_FILE' is not a valid file. Please provide a valid PCAP file path."
    exit 1
fi
So, the script does check for the existence of the provided file.

Validation Steps in the Script:
It verifies that the user provided a valid file path (-f checks if the file exists and is not a directory).
If the file exists, it extracts the file extension to ensure it's a .pcap file:
bash
Copy code
file_extension=${PCAP_FILE##*.}
if [[ "$file_extension" != "pcap" ]]; then
This ensures the file has the correct format for analysis.
If the file doesn't exist or isn't a .pcap file, the script provides appropriate error messages and exits.












ChatGPT can make mistakes. Check