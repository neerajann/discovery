# Network Scanner & Port Scanner

A Python tool to discover devices on a subnet and scan ports on a single host.

Network discovery requires a subnet prefix (e.g., `192.168.1.`).  
Port scanning requires a full IP address (e.g., `192.168.1.10`).  
The script enforces this and returns errors if the wrong format is used.

---

## Usage

### 1. Discover devices in a subnet
Scan `.1` to `.255` in the provided subnet prefix:
    python discover.py -ip 192.168.16.

### 2. Scan ports on a specific device
Scan ports 80 to 100 on a full IP:
    python discover.py -ip 192.168.16.5 -p -s 80 -e 100

### 3. Use custom number of workers (threads)
    python discover.py -ip 192.168.16.5 -p -s 20 -e 80 -m 50

---

## Notes
- Network discovery = subnet prefix only.
- Port scanning = full IP only.
- Windows‑only (uses `ping -n` and `arp -a`).
- The tool validates IP format depending on mode and exits with errors if incorrect.
