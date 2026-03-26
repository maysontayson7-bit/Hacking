 #!/usr/bin/env python
# encoding: utf-8
# author: Lock
# enhanced: 2026
# Network scanner with nmap-like features
import argparse
import socket
import threading
import sys
from datetime import datetime

# Common service ports
COMMON_SERVICES = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5984: 'CouchDB',
    6379: 'Redis',
    8080: 'HTTP-ALT',
    8443: 'HTTPS-ALT',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
}

screenLock = threading.Semaphore(value=1)
open_ports = []


def get_service_name(port):
    """Get service name for common ports"""
    return COMMON_SERVICES.get(port, 'unknown')


def grab_banner(host, port, timeout=2):
    """Try to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner if banner else None
    except:
        return None


def connScan(tgtHost, tgtPort, timeout=1, grab_banner_flag=False):
    """Scan a single port with optional banner grabbing"""
    try:
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connSkt.settimeout(timeout)
        connSkt.connect((tgtHost, tgtPort))
        
        service = get_service_name(tgtPort)
        banner = None
        
        if grab_banner_flag:
            banner = grab_banner(tgtHost, tgtPort, timeout)
        
        screenLock.acquire()
        open_ports.append(tgtPort)
        print('[+] %d/tcp open (%s)' % (tgtPort, service))
        if banner:
            print('    |-> Banner: %s' % banner[:100])
        screenLock.release()
        connSkt.close()
        
    except socket.timeout:
        pass
    except socket.error:
        pass
    except Exception as e:
        pass
    finally:
        try:
            connSkt.close()
        except:
            pass


def parse_ports(port_str):
    """Parse port string: single port, comma-separated, or range (1-1000)"""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            # Range format: 1-1000
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            # Single port
            ports.append(int(part))
    return sorted(list(set(ports)))


def portScan(tgtHost, tgtPorts, threads=50, timeout=1, grab_banner_flag=False):
    """
    Multi-threaded port scanner
    :param tgtHost: Target host
    :param tgtPorts: List of ports to scan
    :param threads: Number of threads
    :param timeout: Connection timeout
    :param grab_banner_flag: Whether to grab service banners
    """
    try:
        tgtIP = socket.gethostbyname(tgtHost)
    except socket.gaierror:
        print("[-] Cannot resolve '%s': Unknown host" % tgtHost)
        return
    
    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        print('\n[*] Scanning target: %s (%s)' % (tgtName[0], tgtIP))
    except:
        print('\n[*] Scanning target: %s' % tgtIP)
    
    print('[*] Scan started at %s' % datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print('[*] Number of ports to scan: %d' % len(tgtPorts))
    print('[*] Timeout: %d second(s)' % timeout)
    
    socket.setdefaulttimeout(timeout)
    
    # Create thread pool
    active_threads = []
    thread_count = 0
    
    for tgtPort in tgtPorts:
        # Wait if too many threads are active
        while len(threading.enumerate()) > threads:
            pass
        
        t = threading.Thread(
            target=connScan, 
            args=(tgtHost, int(tgtPort), timeout, grab_banner_flag)
        )
        t.daemon = True
        t.start()
        active_threads.append(t)
        thread_count += 1
        
        # Print progress
        if thread_count % 100 == 0:
            print('[*] Scanned %d ports...' % thread_count)
    
    # Wait for all threads to complete
    for t in active_threads:
        t.join()
    
    print('[*] Scan completed at %s' % datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print('\n[*] Results Summary:')
    print('[*] Total open ports found: %d' % len(open_ports))
    if open_ports:
        print('[*] Open ports: %s' % ', '.join(str(p) for p in sorted(open_ports)))


def run():
    parser = argparse.ArgumentParser(
        description='Network Scanner - Scan ports like nmap',
        usage='python PortScan.py -H <target> -p <ports>'
    )
    parser.add_argument('-H', '--host', dest='tgtHost', type=str, required=True,
                        help='Target host (IP or hostname)')
    parser.add_argument('-p', '--ports', dest='tgtPorts', type=str, default='1-1000',
                        help='Ports to scan (default: 1-1000). Examples: 80,443 or 1-1000 or 22,80,443-445')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', dest='timeout', type=int, default=1,
                        help='Connection timeout in seconds (default: 1)')
    parser.add_argument('-b', '--banner', dest='grab_banner', action='store_true',
                        help='Grab service banners (slower)')
    
    args = parser.parse_args()
    
    if not args.tgtHost:
        parser.print_help()
        sys.exit(1)
    
    # Parse ports
    try:
        ports = parse_ports(args.tgtPorts)
    except ValueError:
        print("[-] Invalid port format. Use: 80,443 or 1-1000 or 22,80,443-445")
        sys.exit(1)
    
    print("\n" + "="*50)
    print("  Network Scanner v1.1")
    print("="*50)
    
    portScan(args.tgtHost, ports, threads=args.threads, 
             timeout=args.timeout, grab_banner_flag=args.grab_banner)
    
    print("\n" + "="*50)


if __name__ == '__main__':
    run() portScan is a mapscanner that scans specified ports on a target host, similar to nmap. It sts multi-threading for faster scanning and can optionally grab service banners for open ports. The script accepts command-line arguments for target host, ports to scan, number of threads, connection timeout, and whether to grab banners. Results are printed in a user-friendly format with a summary at the end.
        

