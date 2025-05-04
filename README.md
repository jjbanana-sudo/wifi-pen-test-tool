# wifi-pen-test-tool
A Python-based tool for Wi-Fi network reconnaissance and security assessment, designed for educational purposes and authorized penetration testing. This script uses Scapy to scan for wireless networks and perform deauthentication attacks.
DISCLAIMER: This tool is for educational purposes only. Only use it on networks you own or have explicit permission to test. Unauthorized network scanning or attacks may be illegal in your jurisdiction.

Features
Network Scanning: Discover nearby Wi-Fi access points (APs) and associated clients, including SSID, BSSID, channel, encryption type, and signal strength.

Deauthentication Attacks: Send deauthentication packets to disrupt connections (requires monitor mode and packet injection support).

Cross-Platform Support: Works on Linux (recommended) and Windows (with limitations).

Channel Hopping: Automatically scan across Wi-Fi channels (1-14) or focus on a specific channel.

Thread-Safe Design: Uses locks to ensure safe concurrent access to shared data.

Requirements
Python 3.6+

Scapy: Install with pip install scapy

Operating System:
Linux (e.g., Kali Linux, Ubuntu): Recommended for full functionality, including monitor mode and packet injection.

Windows: Limited functionality due to monitor mode restrictions. Requires Npcap and a compatible wireless adapter.

Wireless Adapter: Must support monitor mode and packet injection (e.g., Alfa AWUS036ACH, Realtek RTL8187-based adapters).

Administrator/Root Privileges: Required for packet capture and injection.

Optional Tools:
Aircrack-ng: For setting monitor mode and verifying adapter compatibility.

Npcap (Windows): For packet capture, with WinPcap API compatibility enabled.

Note: The Realtek 8188GU adapter (as used by the project creator) may not support monitor mode on Windows. Linux is strongly recommended for full functionality.

Installation
Linux (Recommended)
Install Dependencies:
bash

sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng
pip3 install scapy

Clone the Repository:
bash

git clone https://github.com/<your-username>/wifi-pentest-tool.git
cd wifi-pentest-tool

Set Up Wireless Adapter:
Plug in your wireless adapter and check its interface name:
bash

iwconfig

Set monitor mode (replace wlan0 with your interface):
bash

sudo airmon-ng start wlan0

This creates a monitor mode interface (e.g., wlan0mon).

Windows
Install Npcap:
Download and install Npcap from https://nmap.org/npcap/.

Enable WinPcap API compatibility and Support raw 802.11 packet injection during installation.

Install Python and Scapy:
powershell

pip install scapy

Clone the Repository:
powershell

git clone https://github.com/<your-username>/wifi-pentest-tool.git
cd wifi-pentest-tool

Check Adapter Compatibility:
Use netsh wlan show interfaces to find your interface name (e.g., Wi-Fi).

Note: Most Windows adapters, including the Realtek 8188GU, do not support monitor mode natively. Consider using Linux or a compatible adapter (e.g., Alfa AWUS036ACH).

Optional: Install Aircrack-ng:
Download from https://www.aircrack-ng.org/.

Extract to C:\aircrack-ng-1.7-win and add the bin folder to your PATH.

Usage
Run the script with administrator/root privileges. The script supports two main commands: scan and deauth.
Examples
Scan for Wi-Fi Networks (Linux, 60 seconds):
bash

sudo python3 wifi_pentest_tool.py -i wlan0mon scan

Scan for 30 Seconds on a Specific Channel (Linux):
bash

sudo python3 wifi_pentest_tool.py -i wlan0mon -t 30 -c 6 scan

Deauthentication Attack (Linux, target AP with BSSID 00:11:22:33:44:55):
bash

sudo python3 wifi_pentest_tool.py -i wlan0mon deauth -b 00:11:22:33:44:55

Scan on Windows (limited functionality):
powershell

C:\path\to\python.exe wifi_pentest_tool.py -i Wi-Fi scan

Command-Line Options
-i, --interface: Wireless interface in monitor mode (e.g., wlan0mon, Wi-Fi).

-t, --scan-time: Scan duration in seconds (default: 60).

-c, --channel: Specific channel to scan (1-14).

scan: Scan for APs and clients.

deauth: Perform deauthentication attack.
-b, --bssid: Target AP MAC address.

-c, --client: Target client MAC address (default: broadcast).

-n, --num-packets: Number of deauth packets (default: 10).

Troubleshooting
Monitor Mode Error:
Linux: Ensure the interface is in monitor mode (sudo airmon-ng start wlan0).

Windows: Most adapters don’t support monitor mode. Use Linux or a compatible adapter.

No Networks Detected:
Verify monitor mode with iwconfig (Linux).

Move closer to Wi-Fi networks or specify a channel (-c).

Permission Denied:
Run with sudo (Linux) or as Administrator (Windows).

Scapy Errors:
Ensure Npcap (Windows) or libpcap (Linux) is installed.

Reinstall Scapy: pip install --upgrade scapy.

Limitations
Windows Support: Limited due to lack of native monitor mode. Requires Npcap and a compatible adapter.

Realtek 8188GU: May not support monitor mode on Windows. Use Linux for better compatibility.

Channel Setting: Not supported on Windows without third-party tools.

For best results, use Kali Linux with a compatible adapter like the Alfa AWUS036ACH.
Contributing
Contributions are welcome! Please:
Fork the repository.

Create a feature branch (git checkout -b feature/YourFeature).

Commit changes (git commit -m 'Add YourFeature').

Push to the branch (git push origin feature/YourFeature).

Open a Pull Request.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments
Built with Scapy for packet manipulation.

Inspired by open-source security tools like Aircrack-ng.

Legal Notice: Always obtain explicit permission before testing any network. Misuse of this tool may violate local laws.

