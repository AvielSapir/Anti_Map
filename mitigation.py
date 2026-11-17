import subprocess
import time
from typing import Set

class MitigationEngine:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.blocked_ips: Set[str] = set()

    def block_ip(self, ip_address: str) -> bool:
        if ip_address in self.blocked_ips or ip_address in ("127.0.0.1", "::1"):
            return False
        
        self.blocked_ips.add(ip_address)
        if self.dry_run:
            return True
            
        try:
            cmd = ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        if ip_address not in self.blocked_ips:
            return False
            
        self.blocked_ips.remove(ip_address)
        if self.dry_run:
            return True
            
        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def flush_all(self):
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
