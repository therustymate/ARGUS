from scapy.all import get_if_list
from scapy.all import get_if_hwaddr
import psutil

IFACE = ""
DEVICE_MAC = ""

def get_preferred_interface():
    global IFACE
    interfaces = get_if_list()

    preferred_order = ["wlan0", "Wi-Fi", "enp3s"]

    for iface in preferred_order:
        for interface, addrs in psutil.net_if_addrs().items():
            if interface == iface:
                IFACE = str(iface)

def get_known_mac():
    global DEVICE_MAC
    mac_address = get_if_hwaddr(IFACE)
    DEVICE_MAC = mac_address

def setup():
    get_preferred_interface()
    get_known_mac()