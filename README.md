# ScanOps 🕵️‍♂️💻 - Network Intelligence Tool

ScanOps is a powerful network intelligence and port scanning tool designed for educational purposes. This tool helps you perform detailed scans, identify operating systems, gather important network information, and more!

Key Features:
---------------
- 🔍 Scan Ports: Scan open ports on a target domain or IP address, and get detailed information about each open port.
- 🧠 OS Identification: Use TTL (Time-To-Live) values to guess the target's operating system.
- 🔐 SSL Certificate Info: Retrieve SSL certificate details of the target domain, including the subject, issuer, and validity period.
- 🌐 DNS & WHOIS Info: Get domain-specific DNS and WHOIS data such as IP address, reverse DNS, registrar, and organization.
- 📊 HTTP Headers: Extract HTTP headers for any domain.
- 📁 Save Reports: All results are saved in an easy-to-read JSON format for future reference.

⚠️ This tool is for educational purposes only. Use responsibly.

Getting Started:
---------------
Follow these steps to set up and use ScanOps locally.

1. Prerequisites:
   --------------
   Make sure you have Python 3.6+ installed. You can download it from python.org.
   ```
   sudo apt install python3 -y

2. Nmap Installation:
   -------------------
   nmap for windows:
   ```
   https://nmap.org/download#windows
   ```
   nmap for macos  :
   ```
   https://nmap.org/download#macosx
   ```
   nmap for linux  :
   ```
   https://nmap.org/download#linux-rpm   

4. Clone the repository:
   ----------------------
   ```
   git clone https://github.com/danishjohngs/ScanOps-.git
   cd ScanOps

5. Set up a Virtual Environment (Recommended):
   -------------------------------------------
   For Windows:
   ```
   python -m venv venv
   .\venv\Scripts\activate
   ```
   For Linux/macOS:
   ```
   python3 -m venv venv
   source venv/bin/activate

6. Install Dependencies:
   ----------------------
   Install the necessary Python packages listed in requirements.txt.
   ```
   pip install -r requirements.txt

7. Run the Tool:
   --------------
   Once dependencies are installed, you're ready to run the ScanOps tool!
   ```
   python ScanOps.py

Usage:
------
Once the tool starts, you will be presented with a menu that offers different scanning options:

1. Scan Network: Scan a network (IP/domain) for open ports.
2. Identify OS: Guess the operating system of a device by analyzing TTL values.
3. Show Scan Report: View previous scan reports.
4. Exit: Exit the tool.


