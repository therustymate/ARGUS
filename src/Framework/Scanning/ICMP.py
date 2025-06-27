from scapy.all import *
from scapy.layers.inet import IP, ICMP
from Framework.Device import DeviceManager
from threading import Thread

import ipaddress
import logging

class Scanner:
    def __init__(self, targetRange: str, timeout: float):
        self.TARGET_RANGE = str(targetRange)
        self.TIMEOUT = float(timeout)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        self.scan()

    def get_ip_list(self, cidr: str):
        ip_net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in ip_net]
    
    def send_icmp(self, target_ip:str, timeout:float):
        packet = IP(dst=target_ip) / ICMP()
        response = sr1(packet, timeout=timeout, iface=DeviceManager.IFACE, verbose=False)
        if response:
            print(f"[*] Found: {response[IP].src}")

    def scan(self):
        threads = []
        for ip_address in self.get_ip_list(self.TARGET_RANGE):
            t = Thread(target=self.send_icmp, args=(ip_address, self.TIMEOUT,), daemon=True)
            t.start()
            threads.append(t)

        for thread in threads:
            thread.join()
        
        print("[*] Scan completed.")
        logging.getLogger("scapy.runtime").setLevel(0)