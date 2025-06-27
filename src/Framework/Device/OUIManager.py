from Framework.Device import SettingsManager

import requests
import os

manufacturer = {}

class OUI:
    def GetManufacturer(mac):
        oui = mac[:8].upper().replace("-", "").replace(":", "")
        return manufacturer.get(oui, "Unknown")
    def DownloadManufacturer(location=SettingsManager.settings["Core.oui.location"]):
        location = str(location)

        url = SettingsManager.settings["Core.oui.url"]
        headers = {
            "User-Agent": SettingsManager.settings["Core.useragent"]
        }
        response = requests.get(url, headers=headers)
        if os.path.exists(location): return

        fileObj = open(location, "wb")
        fileObj.write(response.content)
        fileObj.close()

    def LoadManufacturer(location=SettingsManager.settings["Core.oui.location"]):
        location = str(location)

        if not os.path.exists(location): OUI.DownloadManufacturer()
        fileObj = open(location, "r", encoding="utf-8")
        lines = fileObj.readlines()
        fileObj.close()

        for line in lines:
            line = line.split("\n")[0]
            if "(base 16)" in line:
                parts = line.split("(base 16)")
                oui = parts[0].strip().replace("-", "").upper()
                company = parts[1].strip()
                if oui not in manufacturer:
                    manufacturer[oui] = company

def setup():
    OUI.LoadManufacturer()