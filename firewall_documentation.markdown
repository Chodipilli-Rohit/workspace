# Basic Firewall with IP Blocking Documentation

## Overview
This project implements a Python-based firewall for home lab use, designed to monitor incoming IP traffic, block unauthorized addresses based on defined rules, detect multiple failed connection attempts, and log activities. It uses `scapy` for packet sniffing and `iptables` for IP blocking, with real-time monitoring and logging capabilities.

**Warning**: This is for educational purposes only and requires root privileges (`sudo`) to run. Test in a controlled environment (e.g., virtual machine) with proper authorization to avoid network disruptions.

## Features
1. **IP Monitoring and Blocking**: Monitors incoming packets and blocks IPs based on allow/deny rules or excessive failed attempts.
2. **Rule-Based Access Control**: Supports allow/deny lists defined in a configuration file (`firewall_rules.txt`).
3. **Failed Attempt Detection**: Tracks and logs multiple failed connection attempts, blocking IPs after a threshold (default: 5 attempts in 60 seconds).
4. **Real-Time Monitoring**: Continuously monitors network traffic on a specified interface.
5. **Logging**: Logs all actions (allowed, denied, blocked, unblocked) to `firewall.log` and console for auditing.
6. **Temporary Blocking**: Blocks IPs for a configurable duration (default: 300 seconds).

## Requirements
- **Operating System**: Linux (due to `iptables` dependency)
- **Python Libraries**: `scapy` (`pip install scapy`)
- **Privileges**: Root access (`sudo`) for packet sniffing and `iptables` modifications
- **Test Environment**: Home lab or virtual machine (e.g., VirtualBox, VMware)

## Configuration
- **Rules File**: `firewall_rules.txt` defines allow/deny rules in the format:
  ```
  # Allow List
  allow 192.168.1.0/24
  # Deny List
  deny 10.0.0.0/8
  ```
- **Parameters**:
  - `max_attempts`: Maximum failed attempts before blocking (default: 5).
  - `block_duration`: Duration to block an IP (default: 300 seconds).

## Usage
1. Install dependencies: `pip install scapy`
2. Create or edit `firewall_rules.txt` with desired allow/deny rules.
3. Run the script with root privileges:
   ```bash
   sudo python basic_firewall.py <interface>
   ```
   Example: `sudo python basic_firewall.py eth0`
4. Monitor logs in `firewall.log` and console for real-time activity.
5. Stop the script with `Ctrl+C`.

## How It Works
1. **Initialization**: Loads allow/deny rules from `firewall_rules.txt`.
2. **Packet Monitoring**: Uses `scapy` to sniff packets on the specified interface.
3. **Rule Enforcement**:
   - Allows packets from IPs in the allow list.
   - Denies and blocks packets from IPs in the deny list.
   - Tracks failed attempts for non-allowed IPs and blocks after exceeding `max_attempts`.
4. **Blocking Mechanism**: Uses `iptables` to drop packets from blocked IPs.
5. **Expiration**: Automatically unblocks IPs after `block_duration`.
6. **Logging**: Records all actions (allowed, denied, blocked, unblocked) with timestamps.

## Defense Mechanisms
- **Allow/Deny Rules**: Restrict access to trusted IP ranges, reducing attack surface.
- **Rate Limiting**: Detects and blocks IPs with excessive connection attempts, mitigating brute-force attacks.
- **Logging**: Enables auditing and post-incident analysis.
- **Temporary Blocking**: Prevents permanent lockouts while maintaining security.

## Limitations
- Limited to Linux due to `iptables` dependency.
- Basic detection for failed attempts (based on packet frequency, not protocol-specific logic).
- Requires root privileges, posing risks if misconfigured.
- Does not handle advanced attacks (e.g., DDoS, spoofing) or application-layer vulnerabilities.

## Ethical Considerations
- Use only in authorized environments (e.g., home lab or with explicit permission).
- Unauthorized network monitoring or blocking may violate laws or policies.

## Future Improvements
- Add protocol-specific filtering (e.g., TCP, UDP).
- Implement persistent rule storage in a database.
- Enhance detection with machine learning for anomaly-based blocking.
- Support cross-platform blocking (e.g., Windows Firewall).