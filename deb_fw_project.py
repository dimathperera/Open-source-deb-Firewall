
#!/usr/bin/env python3
# Kali Linux Firewall using nftables (NO DEFAULT BLOCKING)

import json
import subprocess
import re
import signal
import sys
import os
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

RULES_FILE = "firewall_rules.json"
NFT_SAVE_FILE = "/etc/nftables.conf"
BACKUP_FILE = "/tmp/firewall_backup.nft"


class Firewall:
    def __init__(self):
        self.rules = self.load_rules()
        self.backup_original_rules()
        self.init_nftables()
        self.apply_saved_rules()
        
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)
        atexit.register(self.cleanup_on_exit)

    def backup_original_rules(self):
        result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        with open(BACKUP_FILE, "w") as f:
            f.write(result.stdout)

    def restore_backup(self):
        if os.path.exists(BACKUP_FILE):
            with open(BACKUP_FILE, "r") as f:
                ruleset = f.read()
            if ruleset.strip():
                subprocess.run(["nft", "-f", "-"], input=ruleset.encode(), check=False)

    def cleanup_on_exit(self):
        print("\n\n[WARN] Firewall script exiting...")
        if self.rules:
            print(f"  {len(self.rules)} user rules are still active!")
            choice = input("  Remove them? (yes/no): ").strip().lower()
            if choice == "yes":
                self.remove_all_user_rules()
                print("  [OK] All user rules removed")

    def cleanup(self, signum, frame):
        print("\n\n[WARN] INTERRUPT RECEIVED! Cleaning up...")
        self.remove_all_user_rules()
        print("  [OK] Cleanup complete. Exiting.\n")
        sys.exit(0)

    # ---------- LOW LEVEL ----------
    def nft(self, ruleset: str):
        subprocess.run(
            ["nft", "-f", "-"],
            input=ruleset.encode(),
            check=False
        )

    # ---------- INIT NFTABLES - NO DEFAULT BLOCKING ----------
    def init_nftables(self):
        ruleset = """
flush ruleset

table inet firewall {
    chain input {
        type filter hook input priority 0;
        policy accept;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }

    chain forward {
        type filter hook forward priority 0;
        policy accept;
    }
}
"""
        self.nft(ruleset)
        print("[OK] Firewall started - NO DEFAULT BLOCKING")
        print("  All traffic is ALLOWED by default")
        print("  Traffic will only be blocked when you add rules\n")

    # ---------- STORAGE ----------
    def load_rules(self):
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except:
            return []

    def save_rules(self):
        with open(RULES_FILE, "w") as f:
            json.dump(self.rules, f, indent=2)

    def save_rules_to_file(self):
        subprocess.run(f"nft list ruleset > {NFT_SAVE_FILE}_manual", shell=True)
        print(f"  Rules saved to {NFT_SAVE_FILE}_manual")

    # ---------- RULE HANDLING ----------
    def build_rule(self, rule):
        action = rule['action']
        direction = rule.get('direction', 'both')
        
        if direction == 'incoming':
            return self._build_single_rule('input', rule, action)
        elif direction == 'outgoing':
            return self._build_single_rule('output', rule, action)
        else:
            return [
                self._build_single_rule('input', rule, action),
                self._build_single_rule('output', rule, action)
            ]
    
    def _build_single_rule(self, chain, rule, action):
        line = f"add rule inet firewall {chain}"
        
        if chain == 'input' and rule.get('src_ip'):
            line += f" ip saddr {rule['src_ip']}"
        if chain == 'output' and rule.get('dst_ip'):
            line += f" ip daddr {rule['dst_ip']}"
        
        proto = rule.get('proto')
        port = rule.get('dst_port')
        
        if proto == 'icmp':
            line += " ip protocol icmp"
        elif proto in ('tcp', 'udp'):
            line += f" {proto}"
            if port:
                line += f" dport {port}"
        
        line += f" {action}"
        return line

    def add_rule(self, rule):
        rule['id'] = len(self.rules) + 1
        self.rules.append(rule)
        rules_to_apply = self.build_rule(rule)
        
        if isinstance(rules_to_apply, str):
            rules_to_apply = [rules_to_apply]
        
        for nft_rule in rules_to_apply:
            print(f"  -> {nft_rule}")
            self.nft(nft_rule)
        
        self.save_rules()
        print(f"[OK] Rule #{rule['id']} added successfully\n")

    def apply_saved_rules(self):
        for rule in self.rules:
            rules_to_apply = self.build_rule(rule)
            if isinstance(rules_to_apply, str):
                rules_to_apply = [rules_to_apply]
            for nft_rule in rules_to_apply:
                self.nft(nft_rule)

    def remove_rule(self, index):
        if index < 1 or index > len(self.rules):
            print(f"[ERROR] Invalid rule number: {index}\n")
            return False
        
        rule = self.rules[index - 1]
        rule_id = rule.get('id', index)
        print(f"\n[REMOVE] Removing rule #{rule_id}: {self._simplify_rule(rule)}")
        
        rules_to_remove = self.build_rule(rule)
        if isinstance(rules_to_remove, str):
            rules_to_remove = [rules_to_remove]
        
        deleted = False
        for chain in ['input', 'output']:
            result = subprocess.run(
                ["nft", "-a", "list", "chain", "inet", "firewall", chain],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if '# handle' in line:
                    match = True
                    
                    if rule.get('src_ip') and rule['src_ip'] not in line:
                        match = False
                    if rule.get('dst_ip') and rule['dst_ip'] not in line:
                        match = False
                    if rule.get('proto') and rule['proto'] not in line:
                        match = False
                    if rule.get('dst_port') and str(rule['dst_port']) not in line:
                        match = False
                    if rule['action'] not in line:
                        match = False
                    
                    if match:
                        handle_match = re.search(r'# handle (\d+)', line)
                        if handle_match:
                            handle = handle_match.group(1)
                            delete_cmd = f"nft delete rule inet firewall {chain} handle {handle}"
                            print(f"  -> {delete_cmd}")
                            subprocess.run(delete_cmd.split(), check=False)
                            deleted = True
        
        del self.rules[index - 1]
        for i, r in enumerate(self.rules, 1):
            r['id'] = i
        self.save_rules()
        print(f"[OK] Rule #{rule_id} removed\n")
        return True

    def _simplify_rule(self, rule):
        parts = []
        if rule.get('action') == 'accept':
            parts.append("ALLOW")
        else:
            parts.append("BLOCK")
        
        parts.append(rule.get('direction', 'both').upper())
        
        if rule.get('src_ip'):
            parts.append(f"SRC={rule['src_ip']}")
        if rule.get('dst_ip'):
            parts.append(f"DST={rule['dst_ip']}")
        if rule.get('proto'):
            parts.append(rule['proto'].upper())
        if rule.get('dst_port'):
            parts.append(f"PORT={rule['dst_port']}")
        
        return " ".join(parts)

    def remove_all_user_rules(self):
        if not self.rules:
            print("[OK] No user rules to remove\n")
            return True
        
        print(f"\n[REMOVE] Removing {len(self.rules)} user rules...")
        while self.rules:
            self.remove_rule(1)
        
        print("[OK] All user rules removed\n")
        return True

    def flush_all_rules(self):
        print("\n" + "="*60)
        print("[DANGER] This will remove ALL firewall rules!")
        print("="*60)
        confirm = input("Type 'YES' to remove ALL rules: ")
        if confirm == "YES":
            subprocess.run(["nft", "flush", "ruleset"], check=False)
            self.rules = []
            self.save_rules()
            print("[OK] ALL rules flushed - NO FIREWALL ACTIVE!\n")
            return True
        else:
            print("Cancelled\n")
            return False

    def show_rules(self):
        print("\n" + "="*60)
        print("CURRENT NFTABLES RULES (Active in kernel):")
        print("="*60)
        subprocess.run(["sudo", "nft", "list", "ruleset"])
        
        if self.rules:
            print("\n" + "="*60)
            print("USER RULES (Saved):")
            print("="*60)
            for i, rule in enumerate(self.rules, 1):
                print(f"{i}. {self._simplify_rule(rule)}")
        else:
            print("\n[OK] No user rules active")
        print()

    def log_packet(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            print(f"[TCP] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"[UDP] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}")
        elif pkt[IP].proto == 1:
            print(f"[ICMP] {src} -> {dst}")
        else:
            print(f"[IP] {src} -> {dst}")

    def monitor_traffic(self):
        print("\n[MONITOR] Monitoring traffic (Ctrl+C to stop)...\n")
        try:
            sniff(prn=self.log_packet, store=False)
        except KeyboardInterrupt:
            print("\n\n  Stopping monitor...")
            self.cleanup(None, None)


def menu():
    print("""
============================================================
LINUX FIREWALL - Add Rules Only When Needed
============================================================
1.  BLOCK outgoing traffic
2.  BLOCK incoming traffic
3.  ALLOW outgoing traffic
4.  ALLOW incoming traffic
5.  Show all active rules
6.  REMOVE a specific rule
7.  REMOVE ALL user rules
8.  Monitor traffic (live view)
9.  DANGER: FLUSH ALL RULES
10. Save & Exit
============================================================
""")


def create_rule(action_type, direction):
    action = "drop" if action_type == "block" else "accept"
    
    rule = {
        "action": action,
        "direction": direction
    }
    
    print(f"\n[CREATE] Creating {action_type.upper()} rule for {direction.upper()} traffic")
    print("-" * 50)
    
    if direction in ["outgoing", "incoming"]:
        src_ip = input("Source IP (press enter for ANY): ").strip()
        dst_ip = input("Destination IP (press enter for ANY): ").strip()
        rule["src_ip"] = src_ip if src_ip else None
        rule["dst_ip"] = dst_ip if dst_ip else None
    
    proto = input("Protocol (tcp/udp/icmp/any): ").strip().lower()
    
    if proto in ("tcp", "udp"):
        rule["proto"] = proto
        port = input("Port number (press enter for ANY): ").strip()
        rule["dst_port"] = port if port else None
    elif proto == "icmp":
        rule["proto"] = "icmp"
        rule["dst_port"] = None
    else:
        rule["proto"] = None
        rule["dst_port"] = None
    
    print(f"\n[OK] Rule ready")
    return rule


if __name__ == "__main__":
    import atexit
    
    fw = Firewall()
    
    print("="*60)
    print("[INFO] NO DEFAULT BLOCKING - All traffic is allowed")
    print("[INFO] Add block rules only when you need them")
    print("[INFO] Rules auto-cleanup on exit (Ctrl+C)")
    print("="*60)
    print()
    
    try:
        while True:
            menu()
            choice = input("Select option: ").strip()
            
            if choice == "1":
                rule = create_rule("block", "outgoing")
                fw.add_rule(rule)
            elif choice == "2":
                rule = create_rule("block", "incoming")
                fw.add_rule(rule)
            elif choice == "3":
                rule = create_rule("allow", "outgoing")
                fw.add_rule(rule)
            elif choice == "4":
                rule = create_rule("allow", "incoming")
                fw.add_rule(rule)
            elif choice == "5":
                fw.show_rules()
            elif choice == "6":
                if fw.rules:
                    print("\n[LIST] Current rules:")
                    for i, rule in enumerate(fw.rules, 1):
                        print(f"  {i}. {fw._simplify_rule(rule)}")
                    try:
                        num = int(input("\nEnter rule number to remove: "))
                        fw.remove_rule(num)
                    except ValueError:
                        print("[ERROR] Invalid input\n")
                else:
                    print("[INFO] No rules to remove\n")
            elif choice == "7":
                if fw.rules:
                    confirm = input(f"Remove all {len(fw.rules)} user rules? (yes/no): ")
                    if confirm.lower() == "yes":
                        fw.remove_all_user_rules()
                else:
                    print("[INFO] No rules to remove\n")
            elif choice == "8":
                fw.monitor_traffic()
            elif choice == "9":
                fw.flush_all_rules()
            elif choice == "10":
                print("\n[SAVE] Saving...")
                subprocess.run(f"nft list ruleset > {NFT_SAVE_FILE}", shell=True)
                if fw.rules:
                    print(f"\n[WARN] {len(fw.rules)} rules still active!")
                print("Exiting...\n")
                break
            else:
                print("[ERROR] Invalid option\n")
    except KeyboardInterrupt:
        print("\n\n[WARN] Interrupted!")
        fw.cleanup(None, None)
