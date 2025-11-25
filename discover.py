import subprocess
from concurrent.futures import ThreadPoolExecutor
import argparse
import socket
import sys
import threading
import re

# Initialize a lock
lock = threading.Lock()

# Function to validate port numbers
def validate_ports(start, end):
    try:
        start = int(start)
        end = int(end)
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            print("Port numbers must be between 1 and 65535.")
            return False
        return True
    except ValueError:
        print("Invalid port numbers provided.")
        return False

# Check if string is full IP
def is_full_ip(ip):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) is not None

# Check if string is subnet prefix
def is_subnet_prefix(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.$", ip) is not None

# Function to ping a device and get the MAC address and hostname
def ping(ip):
    try:
        response = subprocess.run(["ping", "-n", "1", "-w", "10", ip], stdout=subprocess.DEVNULL)
        if response.returncode == 0:
            arp_output = subprocess.check_output("arp -a", shell=True).decode()
            for line in arp_output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac_address = parts[1]
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                            with lock:
                                print(f"[+] Device discovered at {ip}")
                                print(f"    MAC Address: {mac_address}")
                                print(f"    Hostname: {hostname}")
                        except socket.herror:
                            with lock:
                                print(f"    Hostname: Unknown")
                    break
    except Exception as e:
        with lock:
            print(f"Error with {ip}: {e}")

# Function to scan a range of ports on the target IP address
def scan_ports(target_host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target_host, port))
        if result == 0:
            with lock:
                print(f"Port {port} is open")
        s.close()
    except socket.error as e:
        with lock:
            print(f"Error while scanning port {port}: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="A simple tool to discover devices or scan ports",
        epilog="""Example Usage:

1. Discover devices on the network (ping & MAC):
   python discover.py -ip 192.168.1.

2. Scan ports on a single device:
   python discover.py -ip 192.168.1.10 -p -s 80 -e 100"""
    )

    parser.add_argument("-ip", "--ipaddress", required=True, help="Subnet prefix (192.168.1.) or full IP (192.168.1.10)")
    parser.add_argument("-m", "--MAXWORKERS", default=100, help="Number of max workers")
    parser.add_argument("-p", "--port", action="store_true", help="Enable port scanning")
    parser.add_argument("-s", "--startport", help="Starting port number")
    parser.add_argument("-e", "--endport", help="Ending port number")
    
    args = parser.parse_args()

    # Validate IP usage
    if args.port:
        if not is_full_ip(args.ipaddress):
            print("Error: Port scanning requires a full IP (e.g., 192.168.1.10).")
            sys.exit(1)
        if not args.startport or not args.endport:
            print("You must specify both start and end ports with -s and -e.")
            sys.exit(1)
        if not validate_ports(args.startport, args.endport):
            sys.exit(1)
    else:
        if not is_subnet_prefix(args.ipaddress):
            print("Error: Network discovery requires a subnet prefix (e.g., 192.168.1.).")
            sys.exit(1)

    # Perform the scan
    with ThreadPoolExecutor(max_workers=int(args.MAXWORKERS)) as executor:
        if args.port:
            # Port scanning
            for port in range(int(args.startport), int(args.endport) + 1):
                executor.submit(scan_ports, args.ipaddress, port)
        else:
            # Network discovery
            for i in range(1, 256):
                ip = args.ipaddress + str(i)
                executor.submit(ping, ip)

if __name__ == "__main__":
    main()
