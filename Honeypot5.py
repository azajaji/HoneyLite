import socket
import datetime
import hashlib
import os
import requests
import time
from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Network monitoring configuration
tcp_connections = defaultdict(int)
icmp_requests = defaultdict(int)
attack_details = defaultdict(lambda: {'start_time': None, 'packet_count': 0})

# Malware detection results
malware_detections = []

# Threshold for considering ICMP traffic as a flood attack (packets per second)
ICMP_FLOOD_THRESHOLD = 10  # Adjust based on your network

# File monitoring configuration
VIRUSTOTAL_API_KEY = 'aa088a0a302df23514a46d3118aa3f8a0efe4ea9547651d4f56009fb96b677e2'
DOWNLOADS_DIR = r'C:\Users\Testuser\Downloads'

def packet_handler(packet):
    if not packet.haslayer(IP):
        return  # Skip packets without an IP layer
    
    current_time = datetime.datetime.now()
    src_ip = packet[IP].src

    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        tcp_connections[(src_ip, dst_port)] += 1
        
        # Detect FTP, SSH connection requests, SYN scans, and other TCP connections
        service = "FTP" if dst_port == 21 else "SSH" if dst_port == 22 else "TCP"
        flag = "SYN" if packet[TCP].flags == 'S' else "Other"
        key = (src_ip, dst_port, service, flag)
        
        # Update attack details
        if not attack_details[key]['start_time']:
            attack_details[key]['start_time'] = current_time
        attack_details[key]['packet_count'] += 1
        
        print(f"Detected {service} {flag} from {src_ip} to port {dst_port}")

    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo request
        icmp_requests[src_ip] += 1
        key = (src_ip, 'ICMP', 'Echo Request', 'N/A')  # 'N/A' for flag as it's not applicable
        
        # Update attack details
        if not attack_details[key]['start_time']:
            attack_details[key]['start_time'] = current_time
        attack_details[key]['packet_count'] += 1
        
        print(f"ICMP Echo request detected from {src_ip}")
        if icmp_requests[src_ip] >= ICMP_FLOOD_THRESHOLD:
            print(f"Potential ICMP flood attack detected from IP: {src_ip}")

def generate_report():
    print("\nAttack Report Summary:")
    for key, details in attack_details.items():
        src_ip, port, protocol, flag = key
        start_time = details['start_time']
        packet_count = details['packet_count']
        start_time_formatted = start_time.strftime("%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{protocol} ({flag}) from {src_ip}:{port} - Start: {start_time_formatted}, End: {end_time}, Packets: {packet_count}")

    print("\nMalware Detection Report:")
    for file_path, md5_hash, malicious_count in malware_detections:
        if malicious_count > 0:
            print(f"Malware detected in {file_path} (MD5: {md5_hash}) - {malicious_count} detections")
        else:
            print(f"No malware detected in {file_path} (MD5: {md5_hash})")

# File monitoring functions
class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"Detected new file: {file_path}")
            md5_hash = generate_md5_hash(file_path)
            if md5_hash:
                print(f"MD5 hash: {md5_hash}")
                check_file_virustotal(md5_hash)

def generate_md5_hash(file_path):
    """Generate MD5 hash for the given file, handling permission errors."""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except PermissionError:
        print(f"Permission denied for {file_path}. Skipping file.")
        return None
    except Exception as e:
        print(f"Error generating MD5 for {file_path}: {e}")
        return None

def check_file_virustotal(md5_hash):
    url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"Malware detected for MD5 {md5_hash}: {result['data']['attributes']['last_analysis_stats']['malicious']} detections")
        else:
            print(f"No malware detected for MD5 {md5_hash}.")
    else:
        print(f"Failed to retrieve information from VirusTotal. Status code: {response.status_code}")

def monitor_downloads():
    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, DOWNLOADS_DIR, recursive=False)
    observer.start()
    print(f"This is Sensitive System and Under Porotection")
    print(f"*****A Message to Lure the Attacker*****")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def scan_downloads():
    for filename in os.listdir(DOWNLOADS_DIR):
        file_path = os.path.join(DOWNLOADS_DIR, filename)
        # Check if the file has been checked before
        if file_path not in checked_files and os.path.isfile(file_path):
            print(f"Detected new file: {file_path}")
            md5_hash = generate_md5_hash(file_path)
            if md5_hash:
                print(f"MD5 hash: {md5_hash}")
                check_file_virustotal(md5_hash)
                checked_files.add(file_path)

def main():
    # Start network monitoring in a separate thread
    from threading import Thread
    network_thread = Thread(target=lambda: sniff(prn=packet_handler, store=False), daemon=True)
    network_thread.start()

    # Start file download monitoring in a separate thread
    file_monitor_thread = Thread(target=monitor_downloads, daemon=True)
    file_monitor_thread.start()

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nScript terminated by user.")
    finally:
        generate_report()

if __name__ == "__main__":
    main()
