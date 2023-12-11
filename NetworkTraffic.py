import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.dns import DNS
import pandas as pd
from urllib.parse import urlparse
import re

capture_duration = 30  

output_file = "captured_traffic.csv"
cleaned_output_file = "captured_traffic_cleaned.csv"

captured_packets = []

# Create a function to extract website name from URLs
def extract_website(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme and parsed_url.netloc:
        return parsed_url.netloc
    else:
        return "Not a valid URL"

def packet_capture(packet):
    captured_packets.append(packet)

print(f"Capturing network traffic for {capture_duration} seconds...")
sniff(prn=packet_capture, timeout=capture_duration)

packet_data = []

for packet in captured_packets:
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].summary().split()[0]

        website_name = "Not a valid URL"

        if protocol == "UDP" and packet.haslayer(DNS):
            dns_packet = packet[DNS]
            if dns_packet.qr == 0:
                domain_name = dns_packet.qd.qname.decode("utf-8")
                website_name = extract_website(domain_name)
            else:
                website_name = "Not a DNS query"
        elif protocol == "TCP" and packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode("utf-8", errors="ignore")
            urls = re.findall(r'https?://\S+', raw_data)
            if urls:
                website_name = extract_website(urls[0])
        else:
            website_name = "Not a valid URL"

        timestamp = pd.to_datetime(packet.time, unit='s').strftime('%Y-%m-%d %H:%M:%S')

        packet_info = {
            "Timestamp": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Website Name": website_name,
            "Length": len(packet),
        }
        packet_data.append(packet_info)

df = pd.DataFrame(packet_data)

df.to_csv(output_file, index=False, header=["Timestamp", "Source IP", "Destination IP", "Protocol", "Website Name", "Length"])

print(f"Captured traffic saved to {output_file}")

df_cleaned = pd.read_csv(output_file)
df_cleaned = df_cleaned.drop_duplicates()
df_cleaned = df_cleaned.fillna('Unknown')
df_cleaned.to_csv(cleaned_output_file, index=False)

print(f"Cleaned traffic saved to {cleaned_output_file}")
