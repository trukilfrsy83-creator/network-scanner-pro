# NETSCOPE

> Network Discovery • Traffic Monitoring • Port Assessment • Risk Analysis • Evidence

NETSCOPE is a network security assessment tool designed for authorized environments such as personal networks, labs, and security testing environments.

It combines network discovery, port/service assessment, traffic monitoring with TShark, risk analysis, and evidence collection into one simple interface.

## Features

- 🔎 Network Discovery
- 🌐 Host and device identification
- 🔌 TCP port assessment using Nmap
- 📡 Real packet capture using TShark/Wireshark
- 🛡️ Basic risk analysis
- 📊 Network reports
- 📁 Evidence collection
- 🧩 Modular architecture
- 🖥️ Kali Linux support
- 🐍 Python-based

## Requirements

- Linux
- Python 3
- Nmap
- TShark / Wireshark
- Git

Check the installed tools:

```bash
which nmap
which tshark
nmap --version
tshark --version
Installation

Clone the repository:

git clone https://github.com/trukilfrsy83-creator/network-scanner-pro.git
cd network-scanner-pro

Create a virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install Python dependencies:

pip install -r requirements.txt
Usage

Start NETSCOPE:

python3 netscope.py

Follow the interactive menu to select the required module.

Traffic Monitor

NETSCOPE can use TShark to capture network traffic from an available interface.

Example interfaces may include:

wlan0
eth0
lo
any

For normal Wi-Fi monitoring on a Linux system, select the interface actually connected to your network, such as:

wlan0

Captured traffic can be stored as .pcapng evidence for later analysis with Wireshark.

Network Discovery

The discovery module identifies hosts available on an authorized local network and collects information such as:

IP address
MAC address
Hostname
Vendor
Device information
Online/offline state
Port Assessment

The assessment module uses Nmap to identify accessible TCP services on a target that you are authorized to test.

Example findings can include:

22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https

The results are saved for analysis and reporting.

Risk Analysis

NETSCOPE analyzes discovered services and produces a basic risk assessment.

Example:

Target: 192.168.1.10

22/tcp   SSH
80/tcp   HTTP
443/tcp  HTTPS

Risk: REVIEW REQUIRED

Risk analysis is intended to help security testers prioritize further investigation. It is not a replacement for a professional vulnerability scanner or manual security assessment.

Evidence

Results can include:

results/
├── evidence/
├── reports/
├── scans/
└── captures/

Evidence may include:

JSON reports
CSV reports
Nmap XML results
PCAPNG captures

Generated scan data is excluded from Git using .gitignore.

Project Structure
network-scanner-pro/
│
├── adapters/
│   ├── __init__.py
│   ├── firewall.py
│   └── mock.py
│
├── modules/
│   ├── __init__.py
│   ├── assessment.py
│   ├── discovery.py
│   ├── network.py
│   ├── reports.py
│   └── response.py
│
├── netscope.py
├── scanner.py
├── requirements.txt
├── README.md
└── .gitignore
Security & Authorization

NETSCOPE is intended for:

Your own network
Systems you own
Authorized penetration-testing environments
CTFs and security labs
Educational research

Only scan or monitor systems when you have permission to do so.

Do not use NETSCOPE to access, disrupt, intercept, or compromise networks or devices without authorization.

Platform Support
Linux

Linux is the primary supported platform.

Windows

Windows support may require additional configuration for:

Nmap
TShark/Wireshark
Network interface permissions
macOS

macOS support may require additional permissions and installation of the required networking tools.

Troubleshooting
Nmap not found

Install Nmap:

sudo apt update
sudo apt install nmap

Check:

which nmap
TShark not found

Install Wireshark/TShark:

sudo apt update
sudo apt install tshark

Check:

which tshark
tshark --version
Python dependency missing

Activate the virtual environment:

source .venv/bin/activate

Then:

pip install -r requirements.txt
Permission problems with packet capture

Packet capture may require appropriate Linux permissions.

For troubleshooting, verify:

tshark -D

If your system requires elevated privileges, run the relevant capture operation with the permissions appropriate for your own system.

Development

Clone the repository:

git clone https://github.com/trukilfrsy83-creator/network-scanner-pro.git
cd network-scanner-pro

Create the development environment:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Run:

python3 netscope.py
Roadmap

Planned improvements may include:

Improved device fingerprinting
Better service detection
Advanced traffic statistics
Enhanced risk scoring
HTML reporting
PDF reporting
Dashboard interface
Plugin architecture
Additional defensive network integrations
Improved Windows/macOS compatibility
Disclaimer

NETSCOPE is provided for authorized security testing, defensive security research, and education.

The developer is not responsible for misuse of this software.

License

Choose an appropriate open-source license before publishing the project publicly.

NETSCOPE — Network visibility and security assessment in one tool.
