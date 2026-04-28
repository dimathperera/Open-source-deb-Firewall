#!/usr/bin/env python3
# Debian/Ubuntu/Kali Linux Firewall using nftables

import json
import subprocess
import os
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

RULES_FILE = "firewall_rules.json"
NFT_SAVE_FILE = "/etc/nftables.conf"


class Firewall:

    def __init__(self):
        # Check if running as root
        if os.geteuid() != 0:
            print("ERROR: This script must be run as root (sudo)!")
            exit(1)
            
        self.rules = self.load_rules()
        self.init_nftables()
        self.apply_saved_rules()
        print("Firewall initialized successfully")

    # ---------- LOW LEVEL ----------
    def nft(self, command, input_data=None):
        """Execute nft command and return result"""
        if isinstance(command, str):
            command = command.split()
        
        if input_data:
            result = subprocess.run(command, capture_output=True, text=True, input=input_data)
        else:
            result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0 and result.stderr:
            if "No such file or directory" not in result.stderr:
                print(f"NFT Warning: {result.stderr.strip()}")
        return result

    def nft_rule(self, rule_string):
        """Add a single nftables rule"""
        cmd = ["nft"] + rule_string.split()
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Failed to add rule: {result.stderr}")
            return False
        return True

    # ---------- INIT NFTABLES ----------
    def init_nftables(self):
        """Initialize nftables with base rules"""
        ruleset = """flush ruleset

table inet firewall {
    chain input {
        type filter hook input priority 0;
        policy drop;
        
        # Allow loopback
        iif lo accept
        
        # Allow established/related connections
        ct state established,related accept
        
        # Allow ICMP (ping)
        icmp type echo-request accept
        icmpv6 type echo-request accept
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}"""
        result = self.nft(["nft", "-f", "-"], input_data=ruleset)
        if result.returncode != 0:
            print(f"Failed to initialize nftables: {result.stderr}")
            exit(1)

    # ---------- STORAGE ----------
    def load_rules(self):
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_rules(self):
        with open(RULES_FILE, "w") as f:
            json.dump(self.rules, f, indent=2)

    # ---------- RULE HANDLING ----------
    def build_rule(self, rule):
        """Build a valid nftables rule from rule dictionary"""
        parts = ["add rule inet firewall input"]
        
        # Source IP
        if rule.get("src_ip") and rule["src_ip"]:
            parts.append(f"ip saddr {rule['src_ip']}")
        
        # Destination IP
        if rule.get("dst_ip") and rule["dst_ip"]:
            parts.append(f"ip daddr {rule['dst_ip']}")
        
        # Protocol and port
        proto = rule.get("proto")
        if proto and proto != "any":
            parts.append(proto)
            
            # Destination port
            if rule.get("dst_port") and rule["dst_port"]:
                parts.append(f"dport {rule['dst_port']}")
        
        # Action (accept/drop)
        action = rule.get("action", "drop")
        parts.append(action)
        
        return " ".join(parts)

    def add_rule(self, rule):
        """Add a new firewall rule"""
        # Validate rule
        if "action" not in rule or rule["action"] not in ["accept", "drop"]:
            print("Invalid rule: action must be 'accept' or 'drop'")
            return False
        
        rule_cmd = self.build_rule(rule)
        print(f"Adding rule: {rule_cmd}")
        
        if self.nft_rule(rule_cmd):
            self.rules.append(rule)
            self.save_rules()
            print("Rule added successfully")
            
            # Verify rule was added
            self.verify_rule(rule)
            return True
        else:
            print("Failed to add rule")
            return False

    def apply_saved_rules(self):
        """Apply all saved rules from JSON file"""
        if not self.rules:
            print("No saved rules to apply")
            return
        
        print(f"Applying {len(self.rules)} saved rules...")
        for rule in self.rules:
            rule_cmd = self.build_rule(rule)
            if not self.nft_rule(rule_cmd):
                print(f"Failed to apply rule: {rule}")

    def verify_rule(self, rule):
        """Verify if a rule was actually applied"""
        result = self.nft(["nft", "list", "chain", "inet", "firewall", "input"])
        if result.returncode == 0:
            if rule.get("src_ip") and rule["src_ip"] in result.stdout:
                print("   Rule verified in nftables")
            elif rule.get("dst_ip") and rule["dst_ip"] in result.stdout:
                print("   Rule verified in nftables")
            else:
                print("   Could not verify rule, check with 'nft list ruleset'")

    def delete_rule(self, rule_index):
        """Delete a rule by index"""
        if 0 <= rule_index < len(self.rules):
            removed_rule = self.rules.pop(rule_index)
            self.save_rules()
            
            # Rebuild all rules
            self.init_nftables()
            self.apply_saved_rules()
            print(f"Deleted rule: {removed_rule}")
            return True
        else:
            print("Invalid rule index")
            return False

    def list_rules(self):
        """Display current firewall rules"""
        print("\n" + "="*60)
        print("CURRENT NFTABLES RULES")
        print("="*60)
        result = self.nft(["nft", "list", "chain", "inet", "firewall", "input"])
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Failed to list rules")
        
        print("\n" + "="*60)
        print("SAVED RULES (JSON)")
        print("="*60)
        if self.rules:
            for i, rule in enumerate(self.rules):
                print(f"{i+1}. {rule}")
        else:
            print("No saved rules")

    # ---------- LOGGING ----------
    def log_packet(self, pkt):
        """Log packet information"""
        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        if TCP in pkt:
            print(f"[TCP] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"[UDP] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}")
        elif ICMP in pkt:
            print(f"[ICMP] {src} -> {dst}")
        else:
            print(f"[IP] {src} -> {dst}")

    def monitor_traffic(self, count=0):
        """Monitor network traffic"""
        print("Monitoring traffic (Ctrl+C to stop)")
        print("-" * 60)
        try:
            sniff(prn=self.log_packet, store=False, count=count)
        except KeyboardInterrupt:
            print("\nMonitoring stopped")

    # ---------- TEST FUNCTIONS ----------
    def test_connectivity(self, ip="8.8.8.8"):
        """Test if an IP is reachable"""
        result = subprocess.run(["ping", "-c", "1", "-W", "2", ip], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print(f"SUCCESS: {ip} is reachable")
            return True
        else:
            print(f"FAILED: {ip} is NOT reachable")
            return False

    def test_rule(self, rule):
        """Test if a rule blocks/allows traffic as expected"""
        print(f"\nTesting rule: {rule}")
        
        if rule.get("dst_ip"):
            test_ip = rule["dst_ip"]
        elif rule.get("src_ip"):
            test_ip = rule["src_ip"]
        else:
            print("Cannot test rule without IP address")
            return
        
        print(f"Testing connectivity to {test_ip}...")
        self.test_connectivity(test_ip)


# ---------- UI FUNCTIONS ----------
def menu():
    print("""
======================================
 Debian/Ubuntu/Kali Python Firewall
======================================
 1. Block traffic (DROP)
 2. Allow traffic (ACCEPT)
 3. Show all rules
 4. Delete a rule
 5. Monitor traffic
 6. Test connectivity
 7. Save config and exit
 8. Reset all rules
======================================
""")


def create_rule(action):
    """Interactive rule creation"""
    print(f"\nCreating {action.upper()} rule")
    print("-" * 40)
    
    rule = {"action": "accept" if action == "allow" else "drop"}

    src = input("Source IP (press Enter for any): ").strip()
    dst = input("Destination IP (press Enter for any): ").strip()
    
    if src:
        rule["src_ip"] = src
    if dst:
        rule["dst_ip"] = dst
    
    proto = input("Protocol (tcp/udp/icmp/any): ").strip().lower()
    
    if proto in ("tcp", "udp"):
        rule["proto"] = proto
        port = input("Destination port (press Enter for any): ").strip()
        if port:
            try:
                rule["dst_port"] = int(port)
            except ValueError:
                print("Invalid port number, ignoring port")
    elif proto == "icmp":
        rule["proto"] = "icmp"
    elif proto == "any" or not proto:
        rule["proto"] = None
    else:
        print(f"Unknown protocol '{proto}', ignoring")
        rule["proto"] = None
    
    return rule


# ---------- MAIN ----------
if __name__ == "__main__":
    # Check root privileges first
    if os.geteuid() != 0:
        print("This script must be run with sudo!")
        print("Try: sudo python3 debfw.py")
        exit(1)
    
    # Initialize firewall
    fw = Firewall()
    
    # Main loop
    while True:
        menu()
        choice = input("Select option: ").strip()
        
        if choice == "1":  # Block
            rule = create_rule("block")
            fw.add_rule(rule)
            
            if rule.get("dst_ip") or rule.get("src_ip"):
                test = input("Test this rule? (y/n): ").strip().lower()
                if test == 'y':
                    fw.test_rule(rule)
        
        elif choice == "2":  # Allow
            rule = create_rule("allow")
            fw.add_rule(rule)
        
        elif choice == "3":  # Show rules
            fw.list_rules()
            input("\nPress Enter to continue...")
        
        elif choice == "4":  # Delete rule
            if not fw.rules:
                print("No rules to delete")
            else:
                fw.list_rules()
                try:
                    idx = int(input("Enter rule number to delete: ")) - 1
                    fw.delete_rule(idx)
                except ValueError:
                    print("Invalid input")
        
        elif choice == "5":  # Monitor
            fw.monitor_traffic()
        
        elif choice == "6":  # Test connectivity
            ip = input("Enter IP to test (default: 8.8.8.8): ").strip()
            if not ip:
                ip = "8.8.8.8"
            fw.test_connectivity(ip)
        
        elif choice == "7":  # Save and Exit
            try:
                subprocess.run(f"nft list ruleset > {NFT_SAVE_FILE}", 
                             shell=True, check=True)
                print(f"Rules saved to {NFT_SAVE_FILE}")
            except:
                print("Could not save nftables ruleset")
            
            print("Goodbye!")
            break
        
        elif choice == "8":  # Reset
            confirm = input("This will delete ALL rules! Are you sure? (yes/no): ")
            if confirm.lower() == "yes":
                fw.init_nftables()
                fw.rules = []
                fw.save_rules()
                print("All rules reset to default")
        
        else:
            print("Invalid option, please try again")
        
        print()
