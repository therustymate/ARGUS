from Framework.Client import ClientManager
from Framework.Device import DeviceManager
from Framework.Device import OUIManager

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

import ipaddress
import tabulate

class GeneralMonitor:
    def __init__(self):
        self._default = True
        self._thread = Thread(target=self._listener, daemon=True)
        self._stop = True
        self._log = []

    def _is_private_ip(self, ip_address:str):
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False

    def _handler(self, pkt):
        if pkt.haslayer(Ether):
            if pkt.haslayer(IP):
                ip_address = pkt[IP].src
                mac_address = pkt[Ether].src
                if self._is_private_ip(str(ip_address)) and ip_address not in ClientManager.CLIENTS.keys():
                    ClientManager.add_client(ip_address, mac_address)
            if pkt.haslayer(ARP):
                ip_address = pkt[ARP].psrc
                mac_address = pkt[ARP].hwsrc
                if self._is_private_ip(str(ip_address)) and ip_address not in ClientManager.CLIENTS.keys():
                    ClientManager.add_client(ip_address, mac_address)
            for client in ClientManager.CLIENTS:
                if ClientManager.CLIENTS[client].MAC in [pkt[Ether].src, pkt[Ether].dst]:
                    ClientManager.CLIENTS[client]._packets.append(raw(pkt))
        self._log.append(pkt)

    def _listener(self):
        while True:
            if self._stop == True:
                break
            sniff(iface=DeviceManager.IFACE, prn=self._handler, count=1)

    def start(self):
        self._thread = Thread(target=self._listener, daemon=True)
        self._stop = False
        self._thread.start()
    def stop(self):
        self._stop = True

class PacketRelay:
    def __init__(self):
        self.CLIENT_MAC = str("")
        self.ROUTER_MAC = str("")

        self._default = False
        self._thread = Thread(target=self._activate, daemon=True)
        self._stop = True

    def _manipulate(self, packet, dest_mac):
        packet[Ether].src = DeviceManager.DEVICE_MAC
        packet[Ether].dst = dest_mac

        sendp(packet, iface=DeviceManager.IFACE, verbose=False)

    def _handler(self, packet):
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src

            if src_mac == self.ROUTER_MAC:
                self._manipulate(packet, self.CLIENT_MAC)
            elif src_mac == self.CLIENT_MAC:
                self._manipulate(packet, self.ROUTER_MAC)

    def _activate(self):
        while True:
            if self._stop == True:
                break
            sniff(iface=DeviceManager.IFACE, prn=self._handler, store=False, count=1)

    def setClientMAC(self):
        '''Set router client IPv4 address'''
        self.CLIENT_MAC = input("[?] Enter the client MAC address: ")

    def setRouterMAC(self):
        '''Set router client MAC address'''
        self.ROUTER_MAC = input("[?] Enter the router MAC address: ")

    def info(self, help=False):
        '''Print all addresses in the relay table.'''
        sets = [
            ["Client", self.CLIENT_MAC],
            ["Router", self.ROUTER_MAC]
        ]
        table = tabulate.tabulate(sets, headers=["Device", "MAC Address"], tablefmt="pretty", colalign=("left", "left"))
        print(table)

    def start(self):
        self._thread = Thread(target=self._activate, daemon=True)
        self._stop = False
        self._thread.start()

    def stop(self):
        self._stop = True
