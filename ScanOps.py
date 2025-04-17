import socket
import threading
from queue import Queue
from tqdm import tqdm
import requests
import ipaddress
import time

# Configuration
NUM_THREADS = 100
PORT_RANGE = range(1, 65536)
queue = Queue()

# Function to resolve hostname to IP
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"❌ Could not resolve target: {target}")
        return None

# Function to fetch IP information
def fetch_ip_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        print("\n🌐 IP Info:")
        for key in ['query', 'country', 'regionName', 'city', 'isp', 'org', 'as', 'timezone']:
            print(f"  {key.title()}: {data.get(key, 'N/A')}")
    except Exception as e:
        print(f"❌ Error fetching IP info: {e}")

# Worker function for threads
def scan_port_worker(ip, progress_bar, open_ports):
    while not queue.empty():
        port = queue.get()
        if scan_port(ip, port):
            open_ports.append(port)
        progress_bar.update(1)
        queue.task_done()

# Function to scan a single port
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False

# Master port scanner function
def run_port_scan(ip):
    print(f"\n🔍 Scanning {ip} from port {PORT_RANGE.start} to {PORT_RANGE.stop - 1}...\n")

    open_ports = []
    for port in PORT_RANGE:
        queue.put(port)

    progress_bar = tqdm(total=len(PORT_RANGE), desc="📊 Scanning Ports", unit="port")

    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=scan_port_worker, args=(ip, progress_bar, open_ports))
        thread.daemon = True
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    progress_bar.close()

    if open_ports:
        print("\n✅ Open Ports:")
        for port in open_ports:
            print(f"  - Port {port}")
    else:
        print("\n⚠️ No open ports found.")

# Main function
def main():
    print("🛠️  Domain/IP Info + Port Scanner\n")
    target = input("🌐 Enter domain or IP: ").strip()

    ip = resolve_target(target)
    if not ip:
        return

    fetch_ip_info(ip)
    run_port_scan(ip)

if __name__ == "__main__":
    try:
        start_time = time.time()
        main()
        duration = time.time() - start_time
        print(f"\n⏱️ Scan completed in {duration:.2f} seconds.")
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user.")
