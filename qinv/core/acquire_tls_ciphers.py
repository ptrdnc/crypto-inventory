#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nmap Cipher and Banner Extractor

This script runs an Nmap scan against a specified IP address and port to
enumerate supported SSL/TLS cipher suites and grab the service banner.

It uses Nmap's XML output format and parses it into a Python dictionary.

Requirements:
- Python 3.6+
- The 'nmap' command-line tool must be installed and in your system's PATH.

Usage:
    python3 acquire_tls_ciphers.py.py <ip_address> <port>

Example:
    python3 acquire_tls_ciphers.py.py 1.1.1.1 443
"""

import argparse
from ipaddress import ip_address
from nmap_xml_parser import parse_nmap_xml
import subprocess
import sys
import xml.etree.ElementTree as ET
import json
import sqlite3

def run_nmap_scan(ip_address: str, port: str) -> str:
    """
    Runs an Nmap scan to get cipher suites and service banners.

    Args:
        ip_address: The target IP address to scan.
        port: The target port to scan.

    Returns:
        The XML output from Nmap as a string.
        Returns an empty string if the scan fails.
    """
    print(f"[*] Starting Nmap scan for {ip_address} on port {port}...")
    print("[*] This may take a few moments...")

    # Nmap command arguments:
    # -sV: Probe open ports to determine service/version info
    # --script ssl-enum-ciphers: Run the script to enumerate ciphers
    # -p: Specify the port
    # -oX -: Output in XML format to stdout
    # TODO modify to use ip range
    command = [
        "nmap",
        "-sV",
        "--script",
        "ssl-enum-ciphers",
        "-p",
        port,
        ip_address,
        "-oX",
        "-",
    ]

    try:
        # Execute the command, capture stdout, and decode it as UTF-8
        # We also capture stderr to show potential Nmap errors.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,  # This will raise CalledProcessError if nmap returns a non-zero exit code
            encoding='utf-8'
        )
        print("[+] Nmap scan completed successfully.")
        return result.stdout
    except FileNotFoundError:
        print("[!] Error: 'nmap' command not found.", file=sys.stderr)
        print("[!] Please ensure Nmap is installed and in your system's PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing Nmap: {e}", file=sys.stderr)
        print(f"[!] Nmap stderr:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

def insert_into_db(data):
    ip_address = data["ip_address"]
    port = data["port"]
    banner = data["service_info"]["banner"]
    available_ciphers = []
    for k, ciphers_per_version in data["ssl_ciphers"].items():
        available_ciphers += [c["name"] for c in ciphers_per_version["ciphers"]]

    try:
        conn = sqlite3.connect('database/example.db')  # Creates file if it doesn't exist
        cursor = conn.cursor()

        placeholders = ','.join('?' for _ in available_ciphers)
        # TODO determine the best way to represent cipher_suites 
        # {0,0,0,0} or {ECDHE-RSA-AES128-GCM-SHA256, ...} or {1,2,3,4}
        query = f"SELECT name FROM tls_cipher_suites WHERE name IN ({placeholders})"
        cursor.execute(query, available_ciphers)
        names = [row[0] for row in cursor.fetchall()]

        cursor.execute("""
        INSERT INTO scanned_services (BANNER, IP, PORT, CIPHER_SUITES)
        VALUES(?, ?, ?, ?)
        """,
        (banner, ip_address, port, json.dumps(names)))
        conn.commit()
    except sqlite3.Error as e:
        print("SQLite Error:", e)


def main():
    parser = argparse.ArgumentParser(
        description="Extract SSL/TLS cipher suites and banners using Nmap.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python3 nmap_cipher_parser.py 1.1.1.1 443"
    )
    parser.add_argument("ip_address", help="The target IP address to scan.")
    parser.add_argument("port", help="The target port (e.g., 443).")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    xml_result = run_nmap_scan(args.ip_address, args.port)
    parsed_data = parse_nmap_xml(xml_result)

    print(json.dumps(parsed_data, indent=4))

    insert_into_db(parsed_data)


if __name__ == "__main__":
    main()



