from bs4 import BeautifulSoup
import requests
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.dns import DNS
import pandas as pd
from urllib.parse import urlparse
import re

capture_duration = 30

output_file = "cleaned_traffic.csv"

def extract_website(url):

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        website_name = soup.title.string or urlparse(url).netloc
        if website_name:
            return website_name.strip()
        else:
            return "Not a valid URL"
    except Exception as e:
        print(f"Error extracting website name for {url}: {e}")
        return "Not a valid URL"


def process_packet(packet):

    global packet_data

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].summary().split()[0]
        timestamp = pd.to_datetime(packet.time, unit='s').strftime('%Y-%m-%d %H:%M:%S')

        website_name = "Not a valid URL"
        domain_name = "Not a valid URL"

        if protocol == "TCP":
            if packet.haslayer("Raw"):
                raw_data = packet[Raw].load.decode("utf-8", errors="ignore")
                urls = re.findall(r'https?://\S+', raw_data)
                if urls:
                    for url in urls:
                        website_name = extract_website(url)
                        break

        if not website_name:
            if protocol == "UDP" and packet.haslayer(DNS):
                dns_packet = packet[DNS]
                if dns_packet.qr == 0:
                    domain_name = dns_packet.qd.qname.decode("utf-8")
                    website_name = extract_website(f"http://{domain_name}")

        packet_data.append({
            "Timestamp": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Website Name": website_name,
            "Domain Name": domain_name,
            "Length": len(packet),
        })

packet_data = []
print(f"Capturing network traffic for {capture_duration} seconds...")
sniff(prn=process_packet, timeout=capture_duration)

df = pd.DataFrame(packet_data)
df.dropna(inplace=True)
df.drop_duplicates(inplace=True)

df['Website Name'] = df['Website Name'].str.lower()
df['Website Name'] = df['Website Name'].str.strip()

df.to_csv(output_file, index=False)

print(f"Captured traffic saved to {output_file}")
