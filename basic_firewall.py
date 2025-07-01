import scapy.all as scapy
import subprocess
import logging
import time
from datetime import datetime
from collections import defaultdict
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class BasicFirewall:
    def __init__(self, interface, config_file="firewall_rules.txt", max_attempts=5, block_duration=300):
        self.interface = interface
        self.config_file = config_file
        self.max_attempts = max_attempts  # Max failed attempts before blocking
        self.block_duration = block_duration  # Block duration in seconds
        self.allow_list = set()
        self.deny_list = set()
        self.failed_attempts = defaultdict(list)  # Track failed attempts with timestamps
        self.blocked_ips = {}  # Track blocked IPs with expiration time
        self.load_rules()

    def load_rules(self):
        """Load allow/deny rules from config file."""
        try:
            if not os.path.exists(self.config_file):
                logging.warning(f"Config file {self.config_file} not found. Creating default rules.")
                with open(self.config_file, 'w') as f:
                    f.write("# Allow List\nallow 192.168.1.0/24\n# Deny List\ndeny 10.0.0.0/8\n")
            
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    rule_type, ip_range = line.split()
                    if rule_type.lower() == 'allow':
                        self.allow_list.add(ip_range)
                    elif rule_type.lower() == 'deny':
                        self.deny_list.add(ip_range)
            logging.info("Loaded rules: %s allow, %s deny", self.allow_list, self.deny_list)
        except Exception as e:
            logging.error("Error loading rules: %s", e)
            sys.exit(1)

    def is_ip_in_range(self, ip, ip_range):
        """Check if an IP is within a CIDR range."""
        try:
            ip_addr = scapy.IP(dst=ip).dst
            network = scapy.IP(dst=ip_range).dst
            return ip_addr in network
        except:
            return False

    def block_ip(self, ip):
        """Block an IP using iptables."""
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.blocked_ips[ip] = time.time() + self.block_duration
            logging.warning("Blocked IP: %s for %d seconds", ip, self.block_duration)
        except subprocess.CalledProcessError as e:
            logging.error("Failed to block IP %s: %s", ip, e)

    def unblock_ip(self, ip):
        """Unblock an IP using iptables."""
        try:
            subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            del self.blocked_ips[ip]
            logging.info("Unblocked IP: %s", ip)
        except subprocess.CalledProcessError as e:
            logging.error("Failed to unblock IP %s: %s", ip, e)

    def check_blocked_ips(self):
        """Check and unblock IPs whose block duration has expired."""
        current_time = time.time()
        for ip, expiry in list(self.blocked_ips.items()):
            if current_time > expiry:
                self.unblock_ip(ip)

    def process_packet(self, packet):
        """Process incoming packets and apply firewall rules."""
        if not packet.haslayer(scapy.IP):
            return

        src_ip = packet[scapy.IP].src
        self.check_blocked_ips()

        # Check if IP is explicitly allowed
        for ip_range in self.allow_list:
            if self.is_ip_in_range(src_ip, ip_range):
                logging.info("Allowed packet from %s", src_ip)
                return

        # Check if IP is explicitly denied
        for ip_range in self.deny_list:
            if self.is_ip_in_range(src_ip, ip_range):
                logging.warning("Denied packet from %s (in deny list)", src_ip)
                self.block_ip(src_ip)
                return

        # Track failed attempts for non-allowed IPs
        current_time = time.time()
        self.failed_attempts[src_ip].append(current_time)
        
        # Remove attempts older than 60 seconds
        self.failed_attempts[src_ip] = [t for t in self.failed_attempts[src_ip] if current_time - t < 60]
        
        # Block IP if too many failed attempts
        if len(self.failed_attempts[src_ip]) > self.max_attempts:
            logging.warning("Too many failed attempts from %s (%d attempts)", src_ip, len(self.failed_attempts[src_ip]))
            self.block_ip(src_ip)
            self.failed_attempts[src_ip] = []  # Reset attempts after blocking
        else:
            logging.info("Packet from %s (attempt %d/%d)", src_ip, len(self.failed_attempts[src_ip]), self.max_attempts)

    def start_monitoring(self):
        """Start real-time packet monitoring."""
        logging.info("Starting firewall on interface %s", self.interface)
        try:
            scapy.sniff(iface=self.interface, prn=self.process_packet, store=False)
        except Exception as e:
            logging.error("Error in packet monitoring: %s", e)
            sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python basic_firewall.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    firewall = BasicFirewall(interface)
    firewall.start_monitoring()

if __name__ == "__main__":
    main()