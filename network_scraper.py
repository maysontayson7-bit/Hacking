off
#!/usr/bin/env python3
# encoding: utf-8
# Network Data Scraper - Comprehensive Network Monitoring & Analysis Tool
# Collects network metrics, monitor traffic, device discovery, and performance stats

import socket
import subprocess
import json
import csv
import os
import sys
import time
import re
from datetime import datetime
from collections import defaultdict
import argparse

class NetworkScraper:
    def __init__(self, output_dir='network_data'):
        self.output_dir = output_dir
        self.data = {
            'timestamp': datetime.now().isoformat(),
            'interfaces': {},
            'connections': [],
            'devices': [],
            'dns_queries': [],
            'routes': [],
            'performance': {}
        }
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def get_interfaces(self):
        """Get all network interfaces and their statistics"""
        print("[*] Collecting network interface data...")
        
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True)
            interfaces = {}
            
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface_name = parts[1].strip()
                        if iface_name:
                            interfaces[iface_name] = {'name': iface_name}
            
            # Get IP addresses
            result = subprocess.run(['ip', 'addr'], 
                                  capture_output=True, text=True)
            
            current_iface = None
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_iface = parts[1].strip()
                elif 'inet' in line and current_iface:
                    ip_match = re.search(r'inet\s+(\S+)', line)
                    if ip_match:
                        if 'ip_address' not in interfaces[current_iface]:
                            interfaces[current_iface]['ip_address'] = []
                        interfaces[current_iface]['ip_address'].append(ip_match.group(1))
            
            self.data['interfaces'] = interfaces
            print(f"[+] Found {len(interfaces)} network interfaces")
            return interfaces
            
        except Exception as e:
            print(f"[-] Error getting interfaces: {e}")
            return {}
    
    def get_network_statistics(self):
        """Get network interface statistics"""
        print("[*] Collecting network statistics...")
        
        try:
            result = subprocess.run(['cat', '/proc/net/dev'], 
                                  capture_output=True, text=True)
            
            stats = {}
            for line in result.stdout.split('\n')[2:]:  # Skip header
                if ':' in line:
                    parts = line.split(':')
                    iface = parts[0].strip()
                    data = parts[1].split()
                    
                    if len(data) >= 16:
                        stats[iface] = {
                            'rx_bytes': int(data[0]),
                            'rx_packets': int(data[1]),
                            'rx_errors': int(data[2]),
                            'rx_dropped': int(data[3]),
                            'tx_bytes': int(data[8]),
                            'tx_packets': int(data[9]),
                            'tx_errors': int(data[10]),
                            'tx_dropped': int(data[11])
                        }
            
            self.data['statistics'] = stats
            print(f"[+] Collected statistics for {len(stats)} interfaces")
            return stats
            
        except Exception as e:
            print(f"[-] Error getting statistics: {e}")
            return {}
    
    def get_connections(self):
        """Get active network connections"""
        print("[*] Collecting active connections...")
        
        try:
            result = subprocess.run(['ss', '-tunap'], 
                                  capture_output=True, text=True)
            
            connections = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        conn = {
                            'protocol': parts[0],
                            'state': parts[1] if len(parts) > 5 else 'LISTENING',
                            'local_addr': parts[3] if len(parts) > 3 else parts[2],
                            'remote_addr': parts[4] if len(parts) > 4 else 'N/A'
                        }
                        connections.append(conn)
            
            self.data['connections'] = connections
            print(f"[+] Found {len(connections)} active connections")
            return connections
            
        except Exception as e:
            print(f"[-] Error getting connections: {e}")
            return []
    
    def get_routing_table(self):
        """Get routing table information"""
        print("[*] Collecting routing table...")
        
        try:
            result = subprocess.run(['ip', 'route', 'show'], 
                                  capture_output=True, text=True)
            
            routes = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    routes.append(line.strip())
            
            self.data['routes'] = routes
            print(f"[+] Found {len(routes)} routes")
            return routes
            
        except Exception as e:
            print(f"[-] Error getting routing table: {e}")
            return []
    
    def get_dns_config(self):
        """Get DNS configuration"""
        print("[*] Collecting DNS configuration...")
        
        try:
            dns_servers = []
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            
            self.data['dns_servers'] = dns_servers
            print(f"[+] Found {len(dns_servers)} DNS servers")
            return dns_servers
            
        except Exception as e:
            print(f"[-] Error getting DNS config: {e}")
            return []
    
    def get_open_ports(self):
        """Get listening ports"""
        print("[*] Scanning open ports...")
        
        try:
            result = subprocess.run(['ss', '-tlnp'], 
                                  capture_output=True, text=True)
            
            open_ports = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        local = parts[3]
                        if ':' in local:
                            port = local.split(':')[-1]
                            open_ports.append({
                                'port': port,
                                'protocol': parts[0],
                                'address': local
                            })
            
            self.data['open_ports'] = open_ports
            print(f"[+] Found {len(open_ports)} open ports")
            return open_ports
            
        except Exception as e:
            print(f"[-] Error scanning ports: {e}")
            return []
    
    def get_hostname_info(self):
        """Get hostname and domain information"""
        print("[*] Collecting hostname information...")
        
        try:
            hostname = socket.gethostname()
            fqdn = socket.getfqdn()
            
            self.data['hostname'] = {
                'hostname': hostname,
                'fqdn': fqdn,
                'local_ip': socket.gethostbyname(hostname)
            }
            
            print(f"[+] Hostname: {hostname}")
            return self.data['hostname']
            
        except Exception as e:
            print(f"[-] Error getting hostname: {e}")
            return {}
    
    def get_arp_table(self):
        """Get ARP table (MAC addresses)"""
        print("[*] Collecting ARP table...")
        
        try:
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True)
            
            arp_entries = []
            for line in result.stdout.split('\n'):
                if line.strip() and '(' in line:
                    arp_entries.append(line.strip())
            
            self.data['arp_table'] = arp_entries
            print(f"[+] Found {len(arp_entries)} ARP entries")
            return arp_entries
            
        except Exception as e:
            print(f"[-] Error getting ARP table: {e}")
            return []
    
    def export_json(self, filename=None):
        """Export data to JSON file"""
        if filename is None:
            filename = f"network_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            
            print(f"[+] Data exported to {filepath}")
            return filepath
            
        except Exception as e:
            print(f"[-] Error exporting JSON: {e}")
            return None
    
    def export_csv(self):
        """Export connections and open ports to CSV"""
        print("[*] Exporting data to CSV...")
        
        # Export connections
        try:
            filepath = os.path.join(self.output_dir, 
                                   f"connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
            
            with open(filepath, 'w', newline='') as f:
                if self.data['connections']:
                    writer = csv.DictWriter(f, fieldnames=self.data['connections'][0].keys())
                    writer.writeheader()
                    writer.writerows(self.data['connections'])
            
            print(f"[+] Connections exported to {filepath}")
            
        except Exception as e:
            print(f"[-] Error exporting connections CSV: {e}")
        
        # Export open ports
        try:
            filepath = os.path.join(self.output_dir, 
                                   f"open_ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
            
            with open(filepath, 'w', newline='') as f:
                if self.data['open_ports']:
                    writer = csv.DictWriter(f, fieldnames=self.data['open_ports'][0].keys())
                    writer.writeheader()
                    writer.writerows(self.data['open_ports'])
            
            print(f"[+] Open ports exported to {filepath}")
            
        except Exception as e:
            print(f"[-] Error exporting open ports CSV: {e}")
    
    def print_summary(self):
        """Print summary of collected data"""
        print("\n" + "="*60)
        print("  NETWORK DATA SUMMARY")
        print("="*60)
        
        if 'hostname' in self.data:
            print(f"\n[Hostname]")
            for key, value in self.data['hostname'].items():
                print(f"  {key}: {value}")
        
        if self.data['interfaces']:
            print(f"\n[Network Interfaces] ({len(self.data['interfaces'])})")
            for iface, info in self.data['interfaces'].items():
                print(f"  {iface}: {info}")
        
        if self.data['open_ports']:
            print(f"\n[Open Ports] ({len(self.data['open_ports'])})")
            for port_info in self.data['open_ports'][:10]:  # Show first 10
                print(f"  {port_info['protocol']:6} {port_info['address']:20}")
            if len(self.data['open_ports']) > 10:
                print(f"  ... and {len(self.data['open_ports']) - 10} more")
        
        if self.data['connections']:
            print(f"\n[Active Connections] ({len(self.data['connections'])})")
            for conn in self.data['connections'][:5]:  # Show first 5
                print(f"  {conn['protocol']:6} {conn['state']:15} {conn['local_addr']}")
            if len(self.data['connections']) > 5:
                print(f"  ... and {len(self.data['connections']) - 5} more")
        
        if 'dns_servers' in self.data:
            print(f"\n[DNS Servers]")
            for dns in self.data['dns_servers']:
                print(f"  {dns}")
        
        if 'routes' in self.data:
            print(f"\n[Routes] ({len(self.data['routes'])})")
            for route in self.data['routes'][:3]:
                print(f"  {route}")
            if len(self.data['routes']) > 3:
                print(f"  ... and {len(self.data['routes']) - 3} more")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Network Data Scraper - Collect and analyze network data',
        usage='python network_scraper.py [options]'
    )
    parser.add_argument('-a', '--all', action='store_true', 
                       help='Collect all network data (default)')
    parser.add_argument('-i', '--interfaces', action='store_true',
                       help='Get network interfaces')
    parser.add_argument('-c', '--connections', action='store_true',
                       help='Get active connections')
    parser.add_argument('-p', '--ports', action='store_true',
                       help='Scan open ports')
    parser.add_argument('-r', '--routes', action='store_true',
                       help='Get routing table')
    parser.add_argument('-d', '--dns', action='store_true',
                       help='Get DNS configuration')
    parser.add_argument('-s', '--stats', action='store_true',
                       help='Get network statistics')
    parser.add_argument('-m', '--Mac', dest='mac', action='store_true',
                       help='Get ARP table (MAC addresses)')
    parser.add_argument('-o', '--output', type=str, default='network_data',
                       help='Output directory (default: network_data)')
    parser.add_argument('-f', '--format', type=str, default='json',
                       choices=['json', 'csv', 'both'],
                       help='Export format (default: json)')
    
    args = parser.parse_args()
    
    scraper = NetworkScraper(output_dir=args.output)
    
    # If no options specified, collect all
    if not any([args.interfaces, args.connections, args.ports, args.routes, 
                args.dns, args.stats, args.mac]):
        args.all = True
    
    print("\n" + "="*60)
    print("  Network Data Scraper v1.0")
    print("="*60 + "\n")
    
    try:
        if args.all:
            scraper.get_hostname_info()
            scraper.get_interfaces()
            scraper.get_network_statistics()
            scraper.get_connections()
            scraper.get_routing_table()
            scraper.get_dns_config()
            scraper.get_open_ports()
            scraper.get_arp_table()
        
        else:
            if args.interfaces:
                scraper.get_interfaces()
            if args.connections:
                scraper.get_connections()
            if args.ports:
                scraper.get_open_ports()
            if args.routes:
                scraper.get_routing_table()
            if args.dns:
                scraper.get_dns_config()
            if args.stats:
                scraper.get_network_statistics()
            if args.mac:
                scraper.get_arp_table()
        
        # Export data
        if args.format in ['json', 'both']:
            scraper.export_json()
        if args.format in ['csv', 'both']:
            scraper.export_csv()
        
        # Print summary
        scraper.print_summary()
        
        print("[+] Network scraping completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
