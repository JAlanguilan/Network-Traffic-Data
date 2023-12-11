# Network Traffic Capture and Cleaning Script
This Python script captures network traffic for a specified duration using the Scapy library, processes the captured packets, extracts information such as source IP, destination IP, protocol, and website names (from URLs), and performs basic data cleaning tasks on the captured data.

# Features
- Captures network traffic fora defined duration ('capture_duration variable).
- Extracts information from captured packets:
  - Source IP
  - Destination IP
  - Protocol (UDP/TCP)
  - Website names extracted from URLs (if available)
  - Packet length
- Saves the captured data to a CSV file ('capture_traffic.csv')
- Performs basic data cleaning tasks:
  - Removes duplicate rows based on all columns.
  - Fills missing values with 'Unknown'
- Saves the cleaned data to a new CSV file ('caputered_traffic_cleaned.csv').

# Requirements
- Python 3.X
- Scapy Library
- Pandas Library

# Usage
Install required libraries:
bash:
```
pip install scapy pandas
```
Run the script:
```
python NetworkTraffic.py
```
# Notes
- Ensure appropriate permissions to capture network traffic.
- Adjust 'capture_duration' to the desired capture time.
