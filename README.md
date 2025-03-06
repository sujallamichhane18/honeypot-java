# HoneypotServer

A multi-protocol cybersecurity honeypot built in Java to simulate vulnerable services (SSH, HTTP, FTP, RDP), log attacker interactions, and analyze common attack patterns.

## Overview

This project creates a lightweight honeypot that mimics real services to attract and monitor malicious activity. It’s designed as a learning tool to explore socket programming, protocol simulation, and basic threat intelligence. Deploy it locally or on a server to see how attackers probe systems!

### Features
- **Simulated Services**:  
  - SSH (port 22): Fake SSH login prompt.  
  - HTTP (port 80): Serves a fake login page and logs table at `/logs`.  
  - FTP (port 21): Responds to `USER` and `PASS` commands.  
  - RDP (port 3389): Mimics a Windows RDP login.  
- **Logging**: Tracks IP addresses, timestamps, and attacker inputs in an HTML table.  
- **Attack Analysis**: Identifies top 5 IPs, usernames, and passwords used in attempts.  
- **Deception**: Locks out IPs after 3 failed attempts with fake error messages.  

## Prerequisites
- **Java Development Kit (JDK)**: Version 8 or higher (e.g., OpenJDK 17).  
- **Operating System**: Tested on Windows; should work on Linux/Mac with minor tweaks.  
- **Ports**: Ensure 21, 22, 80, and 3389 are free (or adjust in code).  

## Setup
1. **Clone or Download**:  
   - Clone this repo: `git clone https://github.com/sujallamichhane18/honeypot-java.git`  
   - Or download the ZIP and extract it.  

2. **Compile**:  
   - Open a terminal in the project directory:  
     ```bash
     javac HoneypotServer.java
     java HoneypotServer.java

    Output:
SSH Honeypot running on port 22
HTTP Honeypot running on port 80
FTP Honeypot running on port 21
RDP Honeypot running on port 3389

Test the Services:
SSH: telnet localhost 22 → Enter username/password.
HTTP: Open http://localhost in a browser → Try logging in; view logs at http://localhost/logs.
FTP: ftp localhost → Type USER test and PASS test123.
RDP: telnet localhost 3389 → Enter username/password.
View Logs:
Access http://localhost/logs to see a table of all activity and attack analysis (top IPs, usernames, passwords).
Stop: Press Ctrl + C in the terminal.

Logs
| Timestamp            | IP Address | Service | Details                        |
|----------------------|------------|---------|--------------------------------|
| 2025-03-05T22:00:00  | 127.0.0.1  | FTP     | Username attempt: admin        |
| 2025-03-05T22:00:01  | 127.0.0.1  | FTP     | Password attempt: password123  |


Contributing
Feel free to fork this repo, tweak the code, or suggest improvements via pull requests. Questions? Open an issue!
