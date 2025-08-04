#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Threaded Nmap Cipher and Banner Extractor with Range Support

This script runs parallel Nmap scans against specified IP addresses and ports to
enumerate supported SSL/TLS cipher suites and grab service banners.

Each IP:port pair is scanned in a separate thread for maximum performance.

It supports various input formats similar to nmap:
- Single IP: 192.168.1.1
- IP range: 192.168.1.1-192.168.1.10
- CIDR notation: 192.168.1.0/24
- Single port: 443
- Port list: 80,443,8080
- Port range: 80-443
- All ports: -p- (limited to common SSL/TLS ports for performance)

Requirements:
- Python 3.6+
- The 'nmap' command-line tool must be installed and in your system's PATH.

Usage:
    python3 acquire_tls_ciphers.py <ip_target> <port_spec> [--max-threads N]

Examples:
    python3 acquire_tls_ciphers.py 1.1.1.1 443
    python3 acquire_tls_ciphers.py 192.168.1.0/24 80,443,8080 --max-threads 20
    python3 acquire_tls_ciphers.py 192.168.1.1-192.168.1.10 80-443 --max-threads 50
    python3 acquire_tls_ciphers.py 10.0.0.1 -p- --max-threads 10
"""

import argparse
from ipaddress import ip_address, ip_network, AddressValueError
from nmap_xml_parser import parse_nmap_xml
import subprocess
import sys
import xml.etree.ElementTree as ET
import json
import sqlite3
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

# Common SSL/TLS ports for -p- option to avoid scanning all 65535 ports
COMMON_SSL_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 636, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5671, 5672, 8080, 8443, 8883, 9443
]

@dataclass
class ScanTarget:
    """Represents a single IP:port scan target"""
    ip: str
    port: str
    
    def __str__(self):
        return f"{self.ip}:{self.port}"

@dataclass
class ScanResult:
    """Represents the result of a single scan"""
    target: ScanTarget
    success: bool
    data: Optional[Dict[Any, Any]] = None
    error: Optional[str] = None
    duration: float = 0.0

class ThreadSafeCounter:
    """Thread-safe counter for tracking progress"""
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()
    
    def increment(self):
        with self._lock:
            self._value += 1
            return self._value
    
    @property
    def value(self):
        with self._lock:
            return self._value

def setup_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def parse_ip_target(ip_target: str) -> List[str]:
    """
    Parse IP target specification into a list of IP addresses.
    
    Supports:
    - Single IP: 192.168.1.1
    - IP range: 192.168.1.1-192.168.1.10
    - CIDR notation: 192.168.1.0/24
    
    Args:
        ip_target: The IP target specification
        
    Returns:
        List of IP addresses as strings
    """
    ip_list = []
    
    try:
        # Check if it's a CIDR notation
        if '/' in ip_target:
            network = ip_network(ip_target, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
            # For /32 networks, include the single host
            if network.num_addresses == 1:
                ip_list = [str(network.network_address)]
        
        # Check if it's an IP range (e.g., 192.168.1.1-192.168.1.10)
        elif '-' in ip_target:
            start_ip, end_ip = ip_target.split('-', 1)
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Validate both IPs
            start_addr = ip_address(start_ip)
            end_addr = ip_address(end_ip)
            
            if start_addr > end_addr:
                raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}")
            
            # Generate range
            current = int(start_addr)
            end = int(end_addr)
            while current <= end:
                ip_list.append(str(ip_address(current)))
                current += 1
        
        # Single IP address
        else:
            # Validate it's a valid IP
            ip_address(ip_target)
            ip_list = [ip_target]
            
    except (AddressValueError, ValueError) as e:
        print(f"[!] Error parsing IP target '{ip_target}': {e}", file=sys.stderr)
        sys.exit(1)
    
    return ip_list

def parse_port_spec(port_spec: str) -> List[str]:
    """
    Parse port specification into a list of ports.
    
    Supports:
    - Single port: 443
    - Port list: 80,443,8080
    - Port range: 80-443
    - All ports: -p- (returns common SSL/TLS ports)
    
    Args:
        port_spec: The port specification
        
    Returns:
        List of port numbers as strings
    """
    port_list = []
    
    # Handle all ports case - use common SSL/TLS ports
    if port_spec == '-p-':
        return [str(port) for port in COMMON_SSL_PORTS]
    
    try:
        # Split by comma for multiple port specifications
        port_parts = [part.strip() for part in port_spec.split(',')]
        
        for part in port_parts:
            # Check if it's a range (e.g., 80-443)
            if '-' in part:
                start_port, end_port = part.split('-', 1)
                start_port = int(start_port.strip())
                end_port = int(end_port.strip())
                
                if start_port > end_port:
                    raise ValueError(f"Start port {start_port} is greater than end port {end_port}")
                
                if start_port < 1 or end_port > 65535:
                    raise ValueError(f"Port range {start_port}-{end_port} is outside valid range (1-65535)")
                
                port_list.extend([str(p) for p in range(start_port, end_port + 1)])
            
            # Single port
            else:
                port_num = int(part)
                if port_num < 1 or port_num > 65535:
                    raise ValueError(f"Port {port_num} is outside valid range (1-65535)")
                port_list.append(str(port_num))
                
    except ValueError as e:
        print(f"[!] Error parsing port specification '{port_spec}': {e}", file=sys.stderr)
        sys.exit(1)
    
    return port_list

def run_single_nmap_scan(target: ScanTarget, logger: logging.Logger) -> ScanResult:
    """
    Runs a single Nmap scan for one IP:port pair.

    Args:
        target: ScanTarget containing IP and port
        logger: Logger instance for this thread

    Returns:
        ScanResult containing scan results or error information
    """
    start_time = time.time()
    
    # Nmap command arguments for single target
    command = [
        "nmap",
        "-sV",
        "--script",
        "ssl-enum-ciphers",
        "-p",
        target.port,
        target.ip,
        "-oX",
        "-",
        "--host-timeout", "30s",  # Timeout per host
        "--script-timeout", "20s"  # Timeout per script
    ]

    try:
        logger.debug(f"Starting scan for {target}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,  # Overall timeout
            encoding='utf-8'
        )
        
        duration = time.time() - start_time
        
        if result.returncode != 0:
            error_msg = f"Nmap returned non-zero exit code {result.returncode}"
            if result.stderr:
                error_msg += f": {result.stderr.strip()}"
            logger.warning(f"Scan failed for {target}: {error_msg}")
            return ScanResult(target, False, error=error_msg, duration=duration)
        
        # Parse the XML result
        try:
            parsed_data = parse_nmap_xml(result.stdout)
            logger.debug(f"Successfully scanned {target} in {duration:.2f}s")
            return ScanResult(target, True, data=parsed_data, duration=duration)
            
        except Exception as parse_error:
            error_msg = f"Failed to parse nmap XML: {str(parse_error)}"
            logger.error(f"Parse error for {target}: {error_msg}")
            return ScanResult(target, False, error=error_msg, duration=duration)
            
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        error_msg = "Scan timed out"
        logger.warning(f"Timeout for {target} after {duration:.2f}s")
        return ScanResult(target, False, error=error_msg, duration=duration)
        
    except Exception as e:
        duration = time.time() - start_time
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"Error scanning {target}: {error_msg}")
        return ScanResult(target, False, error=error_msg, duration=duration)

def create_scan_targets(ip_list: List[str], port_list: List[str]) -> List[ScanTarget]:
    """
    Create all IP:port combinations as ScanTarget objects.
    
    Args:
        ip_list: List of IP addresses
        port_list: List of port numbers
        
    Returns:
        List of ScanTarget objects
    """
    targets = []
    for ip in ip_list:
        for port in port_list:
            targets.append(ScanTarget(ip, port))
    return targets

def run_threaded_scans(targets: List[ScanTarget], max_threads: int = 10) -> List[ScanResult]:
    """
    Run nmap scans in parallel threads.
    
    Args:
        targets: List of ScanTarget objects to scan
        max_threads: Maximum number of concurrent threads
        
    Returns:
        List of ScanResult objects
    """
    logger = setup_logging()
    
    print(f"[*] Starting threaded scans for {len(targets)} targets using {max_threads} threads")
    print(f"[*] Estimated time: {len(targets) * 5 / max_threads:.1f}s - {len(targets) * 15 / max_threads:.1f}s")
    
    results = []
    completed_counter = ThreadSafeCounter()
    start_time = time.time()
    
    # Progress reporting function
    def print_progress():
        while completed_counter.value < len(targets):
            time.sleep(2)  # Update every 2 seconds
            elapsed = time.time() - start_time
            completed = completed_counter.value
            if completed > 0:
                avg_time = elapsed / completed
                remaining = len(targets) - completed
                eta = remaining * avg_time
                print(f"[*] Progress: {completed}/{len(targets)} ({completed/len(targets)*100:.1f}%) - ETA: {eta:.1f}s")
    
    # Start progress reporting thread
    progress_thread = threading.Thread(target=print_progress, daemon=True)
    progress_thread.start()
    
    # Run scans in thread pool
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all tasks
        future_to_target = {
            executor.submit(run_single_nmap_scan, target, logger): target 
            for target in targets
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
                completed_counter.increment()
                
                if result.success:
                    logger.info(f"✓ {target} completed in {result.duration:.2f}s")
                else:
                    logger.warning(f"✗ {target} failed: {result.error}")
                    
            except Exception as e:
                error_result = ScanResult(target, False, error=f"Future exception: {str(e)}")
                results.append(error_result)
                completed_counter.increment()
                logger.error(f"✗ {target} exception: {str(e)}")
    
    total_time = time.time() - start_time
    successful_scans = sum(1 for r in results if r.success)
    
    print(f"\n[+] Scan completed in {total_time:.2f}s")
    print(f"[+] Successful scans: {successful_scans}/{len(targets)} ({successful_scans/len(targets)*100:.1f}%)")
    
    return results

def insert_results_into_db(results: List[ScanResult]):
    """
    Insert all scan results into the database.
    
    Args:
        results: List of ScanResult objects
    """
    successful_results = [r for r in results if r.success and r.data]
    
    if not successful_results:
        print("[!] No successful scan results to insert into database")
        return
    
    try:
        conn = sqlite3.connect('example.db')
        cursor = conn.cursor()
        
        inserted_count = 0
        
        for result in successful_results:
            try:
                data = result.data
                
                # Handle the structure returned by your nmap_xml_parser
                if isinstance(data, dict):
                    ip_address = data.get("ip_address", result.target.ip)
                    port = result.target.port
                    
                    # Extract service info
                    service_info = data.get("service_info", {})
                    banner = service_info.get("banner", "")
                    
                    # Extract SSL ciphers
                    ssl_ciphers = data.get("ssl_ciphers", {})
                    available_ciphers = []
                    
                    for version, cipher_data in ssl_ciphers.items():
                        if isinstance(cipher_data, dict) and "ciphers" in cipher_data:
                            available_ciphers.extend([c.get("name", "") for c in cipher_data["ciphers"]])
                    
                    # Query existing cipher suites if any were found
                    if available_ciphers:
                        placeholders = ','.join('?' for _ in available_ciphers)
                        query = f"SELECT name FROM tls_cipher_suites WHERE name IN ({placeholders})"
                        cursor.execute(query, available_ciphers)
                        cipher_names = [row[0] for row in cursor.fetchall()]
                    else:
                        cipher_names = []
                    
                    # Insert the result
                    cursor.execute("""
                    INSERT INTO scanned_services (BANNER, IP, PORT, CIPHER_SUITES)
                    VALUES(?, ?, ?, ?)
                    """, (banner, ip_address, port, json.dumps(cipher_names)))
                    
                    inserted_count += 1
                    
            except Exception as e:
                print(f"[!] Error inserting result for {result.target}: {e}")
                continue
        
        conn.commit()
        print(f"[+] Successfully inserted {inserted_count} scan results into database")
        
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
    finally:
        if conn:
            conn.close()

def main():
    parser = argparse.ArgumentParser(
        description="Extract SSL/TLS cipher suites and banners using threaded Nmap scans.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python3 acquire_tls_ciphers.py 1.1.1.1 443
  python3 acquire_tls_ciphers.py 192.168.1.0/24 80,443,8080 --max-threads 20
  python3 acquire_tls_ciphers.py 192.168.1.1-192.168.1.10 80-443 --max-threads 50
  python3 acquire_tls_ciphers.py 10.0.0.1 -p- --max-threads 10
  
IP Target Formats:
  Single IP:     192.168.1.1
  IP Range:      192.168.1.1-192.168.1.10
  CIDR:          192.168.1.0/24
  
Port Formats:
  Single Port:   443
  Port List:     80,443,8080
  Port Range:    80-443
  All Ports:     -p- (scans common SSL/TLS ports)
  
Threading:
  --max-threads: Controls concurrent scans (default: 10)
                 Higher values = faster scans but more system load"""
    )
    
    parser.add_argument("ip_target", help="The target IP address(es) to scan")
    parser.add_argument("port_spec", help="The target port(s) to scan")
    parser.add_argument("--max-threads", type=int, default=10, 
                       help="Maximum number of concurrent threads (default: 10)")
    parser.add_argument("--quiet", "-q", action="store_true", 
                       help="Reduce output verbosity")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Validate max_threads
    if args.max_threads < 1:
        print("[!] --max-threads must be at least 1", file=sys.stderr)
        sys.exit(1)
    elif args.max_threads > 100:
        print("[!] --max-threads should not exceed 100 for system stability", file=sys.stderr)
        sys.exit(1)
    
    # Parse targets
    ip_list = parse_ip_target(args.ip_target)
    port_list = parse_port_spec(args.port_spec)
    
    # Create scan targets
    targets = create_scan_targets(ip_list, port_list)
    
    if not args.quiet:
        print(f"[*] Created {len(targets)} scan targets")
        print(f"[*] IP addresses: {len(ip_list)}")
        print(f"[*] Ports: {len(port_list)}")
        print(f"[*] Max threads: {args.max_threads}")
        
        if len(targets) > 1000:
            response = input(f"[?] This will create {len(targets)} scans. Continue? (y/N): ")
            if response.lower() != 'y':
                print("Aborted.")
                sys.exit(0)
    
    # Check if nmap is available
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("[!] Error: 'nmap' command not found or not working.", file=sys.stderr)
        print("[!] Please ensure Nmap is installed and in your system's PATH.", file=sys.stderr)
        sys.exit(1)
    
    # Run the threaded scans
    results = run_threaded_scans(targets, args.max_threads)
    
    # Print summary of results
    if not args.quiet:
        print("\n" + "="*60)
        print("SCAN RESULTS SUMMARY:")
        print("="*60)
        
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        
        print(f"Successful scans: {len(successful_results)}")
        print(f"Failed scans: {len(failed_results)}")
        
        if successful_results:
            avg_duration = sum(r.duration for r in successful_results) / len(successful_results)
            print(f"Average scan time: {avg_duration:.2f}s")
            
            # Show sample of successful results
            print(f"\nSample successful results (first 3):")
            for result in successful_results[:3]:
                if result.data:
                    ssl_ciphers = result.data.get("ssl_ciphers", {})
                    cipher_count = sum(len(v.get("ciphers", [])) for v in ssl_ciphers.values())
                    print(f"  {result.target}: {cipher_count} ciphers found")
        
        if failed_results and not args.quiet:
            print(f"\nFailed scans summary:")
            error_counts = {}
            for result in failed_results:
                error_type = result.error.split(':')[0] if result.error else "Unknown"
                error_counts[error_type] = error_counts.get(error_type, 0) + 1
            
            for error_type, count in error_counts.items():
                print(f"  {error_type}: {count} failures")
    
    # Insert results into database
    insert_results_into_db(results)
    
    # Save detailed results to JSON file
    json_results = []
    for result in results:
        json_result = {
            "target": {"ip": result.target.ip, "port": result.target.port},
            "success": result.success,
            "duration": result.duration,
            "data": result.data,
            "error": result.error
        }
        json_results.append(json_result)
    
    output_file = f"scan_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(json_results, f, indent=2)
    
    print(f"\n[+] Detailed results saved to: {output_file}")

if __name__ == "__main__":
    main()