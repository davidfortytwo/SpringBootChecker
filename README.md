# SpringBootChecker
Check for CVE's in Spring
This Python script serves as a Proof of Concept (PoC) for exploiting the CVE-2023-29986 vulnerability in spring-boot-actuator-logview version 0.2.13. The vulnerability allows for Directory Traversal to sibling directories via the LogViewEndpoint.view feature.

# Features:

* Target URL specification
* Proxy support (default to Burp Suite)
* Payloads from file

# Technologies:
* Python 3.x
* requests library

# Installation Guide

Clone the Repository: Clone the project repository to your local machine.

    git clone https://github.com/davidfortytwo/SpringBootChecker/springchecker.git

Navigate to Project Directory: Change to the project directory.

    cd SpringBootChecker

Install Requirements: Install the required Python packages.

    pip install -r requirements.txt


# Usage Guide

Run the Script: Use the following command to run the script.

Run the Script with a Payload File:

    python springchecker.py -t http://target-application -p http://127.0.0.1:8080 -pl payloads.txt

Run the Script Without a Payload File (use default payload):

    python springchecker.py -t http://target-application -p http://127.0.0.1:8080


Options:

    -t: Target URL (e.g., http://target-application:8080)
    -p: Proxy URL (default is http://127.0.0.1:8080)
    -pl: File containing payloads (e.g., payloads.txt)


