import pandas as pd
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.packet import Raw
from urllib.parse import urlparse
import re
import warnings
import threading
import tkinter as tk
from tkinter import messagebox, filedialog

# Initialize packet data list
packet_data = []
# Suppress the XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Function to extract website name
def extract_website(url):
    try:
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return "Not a valid URL"
        
        response = requests.get(url, timeout=5)
        response.encoding = 'utf-8'  # Set encoding to utf-8
        soup = BeautifulSoup(response.content, "lxml")  # Use lxml for XML parsing
        website_name = soup.title.string if soup.title else parsed_url.netloc
        return website_name.strip() if website_name else "Not a valid URL"
    except requests.RequestException as e:
        print(f"Request error extracting website name for {url}: {e}")
        return "Not a valid URL"
    except Exception as e:
        print(f"Error extracting website name for {url}: {e}")
        return "Not a valid URL"

# Function to process each packet
def process_packet(packet):
    global packet_data

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = pd.to_datetime(packet.time, unit='s').strftime('%Y-%m-%d %H:%M:%S')

        website_name = "Not a valid URL"
        domain_name = "Not a valid URL"

        if protocol == 6:  # TCP
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load.decode("utf-8", errors="ignore")
                urls = re.findall(r'https?://\S+', raw_data)
                if urls:
                    website_name = extract_website(urls[0])

        if protocol == 17 and packet.haslayer(DNS):  # UDP and DNS
            dns_packet = packet[DNS]
            if dns_packet.qr == 0:
                domain_name = dns_packet.qd.qname.decode("utf-8")
                website_name = extract_website(f"http://{domain_name}")

        packet_data.append({
            "Timestamp": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Other",
            "Website Name": website_name,
            "Domain Name": domain_name,
            "Length": len(packet),
        })

# Function to start packet capture
def start_capture():
    global packet_data
    packet_data = []
    try:
        capture_duration = int(duration_entry.get())
        status_label.config(text="Capture in progress...", fg="blue")
        start_button.config(state=tk.DISABLED)
        sniff(prn=process_packet, timeout=capture_duration)
        status_label.config(text="Capture completed", fg="green")
        messagebox.showinfo("Info", f"Captured {len(packet_data)} packets")
    except ValueError:
        status_label.config(text="Invalid duration", fg="red")
        messagebox.showerror("Error", "Please enter a valid capture duration.")
    finally:
        start_button.config(state=tk.NORMAL)

# Function to save captured data to CSV
def save_to_csv():
    if packet_data:
        df = pd.DataFrame(packet_data)
        df.dropna(inplace=True)
        df.drop_duplicates(inplace=True)
        df['Website Name'] = df["Website Name"].str.lower().str.strip()

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            try:
                df.to_csv(file_path, index=False)
                messagebox.showinfo("Info", f"Captured traffic saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
    else:
        messagebox.showwarning("Warning", "No data to save")

# Function to run the capture in a separate thread
def run_capture():
    capture_thread = threading.Thread(target=start_capture)
    capture_thread.daemon = True  # Ensure the thread exits when the main program exits
    capture_thread.start()

# Create the main application window
root = tk.Tk()
root.title("Network Traffic Capture")

# Create and place widgets
tk.Label(root, text="Capture Duration (seconds):").grid(row=0, column=0, padx=10, pady=10)
duration_entry = tk.Entry(root)
duration_entry.grid(row=0, column=1, padx=10, pady=10)

start_button = tk.Button(root, text="Start Capture", command=run_capture)
start_button.grid(row=1, column=0, padx=10, pady=10)

save_button = tk.Button(root, text="Save to CSV", command=save_to_csv)
save_button.grid(row=1, column=1, padx=10, pady=10)

status_label = tk.Label(root, text="Ready", fg="green")
status_label.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Start the main event loop
root.mainloop()
