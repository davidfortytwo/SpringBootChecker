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


# Legal Disclaimer

This Proof of Concept (PoC) script is provided for educational and ethical testing purposes only. It is intended to be used by security researchers, penetration testers, and IT professionals who have received explicit written permission to test the security of a specific application.

Unauthorized use of this script against any application or network without explicit permission is illegal and unethical. The authors, maintainers, and contributors of this script are not responsible for any illegal use or consequences, including but not limited to data loss, service disruption, or legal actions.

By using this script, you agree to abide by all applicable local, state, national, and international laws and regulations. You also agree to indemnify and hold harmless the authors, maintainers, and contributors of this script from and against any and all claims, actions, suits, losses, damages, costs, and expenses arising out of or accruing from the use of this script for unauthorized or illegal activities.

If you do not understand or cannot comply with these terms, you are strongly advised not to use this script.
