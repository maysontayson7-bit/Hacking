#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Data Scraper - Discover devices on your local network
Author: Enhanced by AI Assistant
Date: 2026

This script scans your local network to discover active devices,
their IP addresses, MAC addresses, hostnames, and open ports.
"""

import argparse
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import platform
import re
import json
from datetime import datetime


class NetworkScanner:
    def __init__(self, timeout=1, max_threads=50):
        self.timeout = timeout
        self.max_threads = max_threads
        self.devices = []
        self.lock = threading.Lock()

    def get_local_ip(self):
        """Get the local IP address of this machine"""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def get_network_range(self, ip):
        """Get the network range for scanning"""
        try:
            network = ipaddress.ip_network(ip + '/24', strict=False)
            return network
        except:
            # Fallback to common ranges
            ip_parts = ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def ping_host(self, ip):
        """Ping a host to check if it's alive"""
        try:
            # Use system ping command
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-W', str(self.timeout), ip]

            result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=self.timeout + 1)

            return result.returncode == 0
        except:
            return False

    def get_mac_address(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = parts[1] if len(parts) > 1 else parts[0]
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                                return mac
            else:
                # Linux/Mac
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mac = parts[2]
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                                return mac
        except:
            pass
        return "Unknown"

    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def scan_ports(self, ip, ports=[80, 443, 22, 3389]):
        """Scan common ports on a host"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports

    def scan_host(self, ip):
        """Scan a single host comprehensively"""
        device_info = {
            'ip': ip,
            'alive': False,
            'mac': 'Unknown',
            'hostname': 'Unknown',
            'open_ports': [],
            'device_type': 'Unknown'
        }

        # Check if host is alive
        if self.ping_host(ip):
            device_info['alive'] = True

            # Get additional info for alive hosts
            device_info['mac'] = self.get_mac_address(ip)
            device_info['hostname'] = self.get_hostname(ip)
            device_info['open_ports'] = self.scan_ports(ip)

            # Try to identify device type based on MAC
            mac = device_info['mac'].upper()
            if mac != 'UNKNOWN':
                if mac.startswith('00:50:56') or mac.startswith('08:00:27'):
                    device_info['device_type'] = 'Virtual Machine'
                elif mac.startswith('DC:A6:32') or mac.startswith('00:0C:29'):
                    device_info['device_type'] = 'VMware'
                elif mac.startswith('02:42:AC'):
                    device_info['device_type'] = 'Docker Container'
                elif mac.startswith('B8:27:EB') or mac.startswith('DC:A6:32'):
                    device_info['device_type'] = 'Raspberry Pi'
                elif mac.startswith('00:15:5D'):
                    device_info['device_type'] = 'Hyper-V'
                else:
                    device_info['device_type'] = 'Physical Device'

        with self.lock:
            if device_info['alive'] or ip == self.get_local_ip():
                self.devices.append(device_info)
                print(f"[+] Found device: {ip} ({device_info['hostname']}) - {len(device_info['open_ports'])} open ports")

    def scan_network(self, network_range=None):
        """Scan the entire network range"""
        if not network_range:
            local_ip = self.get_local_ip()
            network_range = self.get_network_range(local_ip)

        print(f"[*] Starting network scan on: {network_range}")
        print(f"[*] Local IP: {self.get_local_ip()}")
        print(f"[*] Timeout: {self.timeout}s, Threads: {self.max_threads}")
        print("-" * 60)

        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = [str(ip) for ip in network.hosts()]

            start_time = time.time()

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(self.scan_host, host) for host in hosts]
                for future in as_completed(futures):
                    pass  # Results are collected in self.devices

            end_time = time.time()
            scan_time = end_time - start_time

            print("-" * 60)
            print(f"[*] Scan completed in {scan_time:.2f} seconds")
            print(f"[*] Found {len(self.devices)} active devices")

        except Exception as e:
            print(f"[-] Error during scan: {e}")

    def save_results(self, filename=None):
        """Save scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.json"

        results = {
            'scan_time': datetime.now().isoformat(),
            'total_devices': len(self.devices),
            'devices': self.devices
        }

        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"[+] Results saved to: {filename}")
        return filename

    def print_results(self):
        """Print scan results in a nice format"""
        if not self.devices:
            print("No devices found.")
            return

        print("\n" + "="*80)
        print("NETWORK SCAN RESULTS")
        print("="*80)

        for device in sorted(self.devices, key=lambda x: ipaddress.ip_address(x['ip'])):
            print(f"\nIP Address: {device['ip']}")
            print(f"Hostname: {device['hostname']}")
            print(f"MAC Address: {device['mac']}")
            print(f"Device Type: {device['device_type']}")
            print(f"Status: {'Alive' if device['alive'] else 'Unknown'}")
            if device['open_ports']:
                print(f"Open Ports: {', '.join(map(str, device['open_ports']))}")
            else:
                print("Open Ports: None found")
            print("-" * 40)


def main():
    parser = argparse.ArgumentParser(
        description='Network Data Scraper - Discover devices on your local network',
        usage='python network_scanner.py [options]'
    )
    parser.add_argument('-r', '--range', dest='network_range',
                        help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=1,
                        help='Timeout for ping requests (default: 1)')
    parser.add_argument('-m', '--max-threads', dest='max_threads', type=int, default=50,
                        help='Maximum number of threads (default: 50)')
    parser.add_argument('-s', '--save', dest='save_file',
                        help='Save results to JSON file')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (less output)')

    args = parser.parse_args()

    scanner = NetworkScanner(timeout=args.timeout, max_threads=args.max_threads)

    print("Network Data Scraper v1.0")
    print("=" * 40)

    scanner.scan_network(args.network_range)

    if not args.quiet:
        scanner.print_results()

    if args.save_file or input("\nSave results to file? (y/n): ").lower() == 'y':
        filename = args.save_file or None
        scanner.save_results(filename)


if __name__ == '__main__':
    main()