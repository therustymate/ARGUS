from Framework.Device import OUIManager

class Client:
    def __init__(self):
        self.IP = "Unknown"
        self.MAC = "Unknown"
        self.Manufacturer = "Unknown"
        self._packets = []

def add_client(ip_address:str, mac_address:str):
    CLIENTS[ip_address] = Client()
    CLIENTS[ip_address].IP = str(ip_address)
    CLIENTS[ip_address].MAC = str(mac_address)
    CLIENTS[ip_address].Manufacturer = OUIManager.OUI.GetManufacturer(mac_address)

CLIENTS = {}