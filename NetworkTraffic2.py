import os
from scapy.all import *
from scapy.layers.inet import IP
import pandas as pd

# Define the duration for capturing traffic (in seconds)
capture_duration = 3600  # 1 hour

# Define the output file for captured data
output_file = "captured_traffic.csv"

# Create a list to store captured packets
captured_packets = []

# Create a packet capture function
def packet_capture(packet):
    captured_packets.append(packet)

# Start capturing packets
print(f"Capturing network traffic for {capture_duration} seconds...")
sniff(prn=packet_capture, timeout=capture_duration)

# Convert the captured packets to a DataFrame for formatting
packet_data = []

for packet in captured_packets:
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].summary().split()[0]
    else:
        src_ip = dst_ip = protocol = "Unknown"

    packet_info = {
        "Timestamp": packet.time,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Protocol": protocol,
        "Length": len(packet),
    }
    packet_data.append(packet_info)

# Create a DataFrame
df = pd.DataFrame(packet_data)

# Save the DataFrame to a CSV file
df.to_csv(output_file, index=False)

print(f"Captured traffic saved to {output_file}")
