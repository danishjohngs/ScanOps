import socket
import ssl
import whois
import json
import requests
import time
import concurrent.futures
import ipaddress
import sys
import os
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    os.system("pip install dnspython")
    import dns.resolver
    import dns.reversename

try:
    from tqdm import tqdm
except ImportError:
    os.system("pip install tqdm")
    from tqdm import tqdm

# Red ASCII banner
BANNER = f"""
{Fore.RED}
  ██████  ▄████▄   ▄▄▄       ███▄    █  ▒█████   ██▓███    ██████ 
▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ ▒██▒  ██▒▓██░  ██▒▒██    ▒ 
░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▒██░  ██▒▓██░ ██▓▒░ ▓██▄   
  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▒██   ██░▒██▄█▓▒ ▒  ▒   ██▒
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░░ ████▓▒░▒██▒ ░  ░▒██████▒▒
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░  ░ ▒ ▒░ ░▒ ░     ░ ░▒  ░ ░
░  ░  ░  ░          ░   ▒      ░   ░ ░ ░ ░ ░ ▒  ░░       ░  ░  ░  
      ░  ░ ░            ░  ░         ░     ░ ░                 ░  
         ░                                                         
{Fore.YELLOW}[*] ScanOps - Network Intelligence Tool
⚠️  Use this tool responsibly. For educational use only. ⚠️
"""

MENU = f"""
{Fore.LIGHTMAGENTA_EX}╔═════════════════════════════════════════════════════════════════════════╗
║               {Fore.WHITE}ScanOps v1.0 - Network Intelligence & Port Scanner               {Fore.LIGHTMAGENTA_EX}║
╚═════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.RED}1.{Fore.WHITE} 🔍 Scan Network
{Fore.RED}2.{Fore.WHITE} 🧠 Identify OS of a Device
{Fore.RED}3.{Fore.WHITE} 🧾 Show Scan Report
{Fore.RED}4.{Fore.WHITE} 🚪 Exit
"""

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(Fore.RED + "[!] Could not resolve domain.")
        return None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore")
            except:
                banner = "No banner"
            return (port, service, banner.strip())
    except:
        return None

def accurate_port_scan(ip, start_port, end_port):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        port_range = list(range(start_port, end_port + 1))
        futures = [executor.submit(scan_port, ip, port) for port in port_range]
        for f in tqdm(concurrent.futures.as_completed(futures), total=len(port_range),
                      desc=f"\n{Fore.CYAN}🔍 Scanning ports {start_port}-{end_port}",
                      bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.RED, Fore.RESET)):
            result = f.result()
            if result:
                open_ports.append(result)
    return open_ports

def dns_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        rev_name = dns.reversename.from_address(ip)
        rev_dns = str(dns.resolver.resolve(rev_name, "PTR")[0])
        return {"IP Address": ip, "Reverse DNS": rev_dns}
    except:
        return {"IP Address": domain, "Reverse DNS": "N/A"}

def whois_info(domain):
    try:
        w = whois.whois(domain)
        return {"Registrar": w.registrar or "N/A", "Org": w.org or "N/A", "Name": w.name or "N/A"}
    except:
        return {"Registrar": "N/A", "Org": "N/A", "Name": "N/A"}

def ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "Subject": cert.get("subject", (("CN", "N/A"),))[0][1],
                "Issuer": cert.get("issuer", (("CN", "N/A"),))[0][1],
                "Valid From": cert.get("notBefore", "N/A"),
                "Valid Till": cert.get("notAfter", "N/A")
            }
    except:
        return {"Subject": "N/A", "Issuer": "N/A", "Valid From": "N/A", "Valid Till": "N/A"}

def http_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=3)
        return dict(r.headers)
    except:
        return {}

def osint_data(ip):
    return {
        "ISP": "N/A",
        "Org": "N/A",
        "OS": "N/A",
        "Hostnames": [],
        "Tags": []
    }

def identify_os(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(2)
        s.sendto(b"\x08\x00\xf7\xff\x00\x00\x00\x00", (ip, 1))  # ICMP Echo Request
        data, addr = s.recvfrom(1024)
        ttl = data[8]
        print(Fore.YELLOW + f"[+] TTL: {ttl}")

        if ttl >= 128:
            os_guess = "Windows"
        elif ttl >= 64:
            os_guess = "Linux/Unix"
        else:
            os_guess = "Unknown"

        print(Fore.RED + f"[+] Guessed OS: {os_guess}")
    except PermissionError:
        print(Fore.RED + "[!] Requires administrator/root privileges to perform OS fingerprinting (ICMP).")
    except:
        print(Fore.RED + "[!] Could not identify OS.")

def save_report(report):
    with open("ScanOpsLOOT.json", "w") as f:
        json.dump(report, f, indent=4)

def main():
    confirm = input(Fore.YELLOW + "[?] This tool is for educational purposes only. Do you agree? (y/n): ").strip().lower()
    if confirm != 'y':
        print(Fore.RED + "[!] Exiting. Educational consent not given.")
        return

    print(BANNER)
    while True:
        print(MENU)
        choice = input(Fore.RED + "[?] Select an option to proceed: " + Fore.WHITE)
        if choice == "1":
            target = input(Fore.RED + "[+] Enter domain or IP for scanning: " + Fore.WHITE)
            scan_type = input(Fore.RED + "[+] Select scan depth:\n[1] Quick Scan (Ports 1-1024)\n[2] Full Scan (Ports 1-65535)\nChoose [1/2]: " + Fore.WHITE)
            port_range = (1, 1024) if scan_type == "1" else (1, 65535) if scan_type == "2" else None
            if not port_range:
                print(Fore.RED + "[!] Invalid scan depth selection.")
                continue

            ip = resolve_domain(target)
            if not ip:
                continue

            print(Fore.LIGHTYELLOW_EX + f"[*] Target domain/IP: {target}\n")
            start_time = time.time()
            open_ports = accurate_port_scan(ip, *port_range)

            print(Fore.LIGHTGREEN_EX + "\n[+] Open Ports:")
            for port, service, banner in open_ports:
                print(f"   [+] Port {port} - {service} - Banner: {banner.splitlines()[0] if banner else 'N/A'}")

            dns_data = dns_info(target)
            whois_data = whois_info(target)
            ssl_data = ssl_info(target)
            headers_data = http_headers(target)
            osint = osint_data(ip)

            end_time = time.time()
            duration = end_time - start_time

            report = {
                "IP": target,
                "open_ports": [(p, s) for p, s, b in open_ports],
                "dns_info": dns_data,
                "whois_info": whois_data,
                "ssl_info": ssl_data,
                "http_headers": headers_data,
                "osint_data": osint,
                "duration": duration
            }

            print(Fore.CYAN + "\n[+] OSINT Data:")
            for k, v in osint.items():
                print(f"   [*] {k}: {v}")

            print(Fore.CYAN + "\n[+] DNS Information:")
            for k, v in dns_data.items():
                print(f"   [*] {k}: {v}")

            print(Fore.CYAN + "\n[+] WHOIS Information:")
            for k, v in whois_data.items():
                print(f"   [*] {k}: {v}")

            print(Fore.CYAN + "\n[+] SSL Certificate Info:")
            for k, v in ssl_data.items():
                print(f"   [*] {k}: {v}")

            print(Fore.CYAN + "\n[+] HTTP Headers:")
            for k, v in headers_data.items():
                print(f"   [*] {k}: {v}")

            print(Fore.LIGHTGREEN_EX + f"\n[+] Scan complete in {duration:.2f} seconds")
            save_report(report)
            print(Fore.YELLOW + "[*] Report saved as ScanOpsLOOT.json")
            print("\n" + "=" * 60 + "\n")

        elif choice == "2":
            ip = input(Fore.RED + "[+] Enter IP address to identify OS: " + Fore.WHITE)
            identify_os(ip)

        elif choice == "3":
            try:
                with open("ScanOpsLOOT.json") as f:
                    data = json.load(f)
                    print(json.dumps(data, indent=4))
            except:
                print(Fore.RED + "[!] No report found.")

        elif choice == "4":
            print(Fore.YELLOW + "Exiting ScanOps...")
            break

        else:
            print(Fore.RED + "[!] Invalid choice")

if __name__ == "__main__":
    main()
