#!/usr/bin/env python3

import argparse
import socket
import threading
import re
import sys
import time
import json

try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

lock = threading.Lock()  

def parse_ip_range(ip_range_str):
    if ',' in ip_range_str:
        parts = ip_range_str.split(',')
        all_ips = []
        for part in parts:
            all_ips.extend(parse_ip_range(part.strip()))
        return all_ips
    
    # dash range 
    if '-' in ip_range_str:
        start_ip, end_ip = ip_range_str.split('-')
        start_segments = list(map(int, start_ip.strip().split('.')))
        end_segments = list(map(int, end_ip.strip().split('.')))
        start_num = (start_segments[0] << 24) + (start_segments[1] << 16) \
                    + (start_segments[2] << 8) + start_segments[3]
        end_num = (end_segments[0] << 24) + (end_segments[1] << 16) \
                  + (end_segments[2] << 8) + end_segments[3]
        
        if start_num > end_num:
            start_num, end_num = end_num, start_num
        
        ip_list = []
        for ip_int in range(start_num, end_num + 1):
            d = ip_int & 255
            c = (ip_int >> 8) & 255
            b = (ip_int >> 16) & 255
            a = (ip_int >> 24) & 255
            ip_list.append(f"{a}.{b}.{c}.{d}")
        return ip_list
    
    return [ip_range_str]

def parse_port_range(port_range_str):
    ports = set()
    parts = port_range_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start_port, end_port = part.split('-')
            start_port, end_port = int(start_port), int(end_port)
            for p in range(start_port, end_port + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(list(ports))

def banner_grab(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)
            return data.decode(errors="ignore").strip()
    except:
        return None

def tcp_connect_scan(ip, port, timeout, retries=1, verbose=False, banner=False):
    result = {"port": port, "status": "closed", "banner": None}
    for attempt in range(retries):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            result["status"] = "open"
            s.close()
            if banner:
                result["banner"] = banner_grab(ip, port, timeout)
            break  
        except socket.timeout:
            if verbose:
                with lock:
                    print(f"[DEBUG] Port {port} timeout (attempt {attempt+1}/{retries})")
        except ConnectionRefusedError:
            break
        except Exception as e:
            if verbose:
                with lock:
                    print(f"[DEBUG] Error scanning port {port}: {e}")
        finally:
            s.close()
    return result

def syn_scan(ip, port, timeout, retries=1, verbose=False, banner=False):
    """
    Perform a SYN (half-open) scan using scapy. Requires root privileges.
    """
    if not SCAPY_AVAILABLE:
        return {"port": port, "status": "unavailable", "banner": None}
    
    result = {"port": port, "status": "closed", "banner": None}
    for attempt in range(retries):
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response is None:
            if verbose:
                with lock:
                    print(f"[DEBUG] No response for SYN scan on port {port}. Attempt {attempt+1}/{retries}.")
            continue
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                result["status"] = "open"
                
                rst_pkt = IP(dst=ip) / TCP(dport=port, flags="R")
                sr1(rst_pkt, timeout=1, verbose=0)
                
                if banner:
                    result["banner"] = banner_grab(ip, port, timeout)
                break
            elif response.getlayer(TCP).flags == 0x14:
                # RST => closed
                break
    return result

def worker_scan(ip, port, scan_type, timeout, retries, verbose, banner, results):
    if scan_type == "connect":
        scan_res = tcp_connect_scan(ip, port, timeout, retries, verbose, banner)
    elif scan_type == "syn":
        scan_res = syn_scan(ip, port, timeout, retries, verbose, banner)
    else:
        scan_res = {"port": port, "status": "unknown", "banner": None}
    
    with lock:
        results.append(scan_res)
        if verbose and scan_res["status"] == "open":
            print(f"[VERBOSE] Found open port {port} on {ip}")

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def main():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP(s) or IP range(s). E.g., 192.168.1.1 or 192.168.1.1-192.168.1.5 or multiple with commas.")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port(s) to scan. E.g., 80,443 or 1-1024")
    parser.add_argument("-s", "--scan-type", choices=["connect", "syn"], default="connect",
                        help="Scan type: connect (TCP connect) or syn (SYN half-open). Default is connect.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output.")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file name. If omitted, results printed to console.")
    parser.add_argument("-r", "--retry", default=1, type=int,
                        help="Number of retries on failed connection attempts. Default 1.")
    parser.add_argument("--timeout", default=2, type=float,
                        help="Timeout for each port scan attempt in seconds. Default 2s.")
    parser.add_argument("-n", "--no-resolve", action="store_true",
                        help="Disable reverse DNS resolution.")
    parser.add_argument("--banner", action="store_true",
                        help="Enable banner grabbing on open ports.")
    
    args = parser.parse_args()
    
    targets = parse_ip_range(args.target)
    ports = parse_port_range(args.ports)
    scan_results = []
    
    # Start scanning
    threads = []
    start_time = time.time()
    
    for ip in targets:
        # Optional reverse DNS
        display_name = ip if args.no_resolve else resolve_hostname(ip)
        
        if args.verbose:
            print(f"\n[INFO] Scanning {display_name} ({ip}) on ports {args.ports} using {args.scan_type} scan...")
        
        for port in ports:
            th = threading.Thread(
                target=worker_scan,
                args=(ip, port, args.scan_type, args.timeout, args.retry,
                      args.verbose, args.banner, scan_results)
            )
            th.start()
            threads.append(th)
    
    for th in threads:
        th.join()
    
    end_time = time.time()
    
    organized_results = {}
    for ip in targets:
        organized_results[ip] = []
    for res in scan_results:
        pass

    out = {}
    for ip in targets:
        out[ip] = []
    for scan_res in scan_results:
        pass
    
   
    open_ports_info = []
    for res in scan_results:
        if res.get("status") == "open":
            open_ports_info.append(res)
    
    # Print or save results:
    if args.output is None:
        print("\nScan complete. Open ports found:")
        for r in open_ports_info:
            port = r["port"]
            status = r["status"]
            banner = r["banner"]
            print(f"    Port {port} -> {status}{' (banner: '+banner+')' if banner else ''}")
        print(f"\nScan took {end_time - start_time:.2f} seconds.")
    else:
        with open(args.output, "w") as f:
            json.dump(scan_results, f, indent=2)
        print(f"[INFO] Results saved to {args.output}")
        print(f"Scan took {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()