from scapy.all import *
from scapy.layers.l2 import ARP
from Framework.Device import DeviceManager

class Scanner:
    def __init__(self, targetRange:str, timeout: float):
        self.TARGET_RANGE = str(targetRange)
        self.TIMEOUT = float(timeout)
        self.scan()

    def scan(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.TARGET_RANGE)
        ans, unans = srp(packet, timeout=self.TIMEOUT, iface=DeviceManager.IFACE, verbose=False)
        
        print("[*] Scan completed.")