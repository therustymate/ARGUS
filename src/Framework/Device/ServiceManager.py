from Framework.MITM import ARP as MITM_arp
from Framework.Monitoring import Ethernet as Monitoring_eth

Services = {}

def setup():
    Services["arp.spoof"] = MITM_arp.ARPSpoofer()
    Services["eth.monitor"] = Monitoring_eth.GeneralMonitor()
    Services["eth.relay"] = Monitoring_eth.PacketRelay()

    for name, instance in Services.items():
        if getattr(instance, "_default", False):
            instance.start()