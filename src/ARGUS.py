GLOBAL_TITLE = """
████████████████████████████       █████  ██████   ██████  ██    ██ ███████      ████████████████████████████
                                  ██   ██ ██   ██ ██       ██    ██ ██           
        ████████████████████      ███████ ██████  ██   ███ ██    ██ ███████      ██████████████████████
                                  ██   ██ ██   ██ ██    ██ ██    ██      ██      
                ████████████      ██   ██ ██   ██  ██████   ██████  ███████      ████████████

                
A.R.G.U.S - Advanced Recon Gathering for Universal Surveillance
Prsent By @therustymate
"""

GLOBAL_DISCLAIMER = """
[Disclaimer]
This software is intended exclusively for educational purposes and ethical cybersecurity research.
It is designed to help users understand potential vulnerabilities in networks so they can improve their security.
By using this software, you agree to use it in compliance with all applicable laws and regulations.
Unauthorized use, distribution, or deployment of this software against any system without the explicit permission of the system owner is strictly prohibited and may result in criminal and civil penalties.
The creator(s) of this software assume no liability and are not responsible for any misuse or damages arising from the use of this software.
Always obtain proper authorization before testing or analyzing systems using this software.
"""

# ----------------------------------------------------------------------------

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# ----------------------------------------------------------------------------

import traceback
import tabulate
import psutil
import socket
import logging
import requests
import socks
import shlex
import os
import sys

# ----------------------------------------------------------------------------

from Framework import *
from Framework.Device import DeviceManager
from Framework.Device import OUIManager
from Framework.Device import ServiceManager
from Framework.Device import SettingsManager
from Framework.Client import ClientManager

from Framework.Scanning import ARP as ARPScanner
from Framework.Scanning import ICMP as ICMPScanner
from Framework.Scanning import TCP as TCPScanner
from Framework.Scanning import UDP as UDPScanner

# ----------------------------------------------------------------------------

ORIGIN_SOCKET = socket.socket
Local_Version = "3.2.0"
SERVICES = {}

class Shell:
    class device:
        def list(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''List devices (interfaces)''', ["N/A"]]
            try:
                devices = []
                for interface, addrs in psutil.net_if_addrs().items():
                    mac_address = None
                    ip_address = None
                    ipv6_addr = None
                    status = "Unknown"

                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            mac_address = addr.address
                        elif addr.family == socket.AF_INET:
                            ip_address = addr.address
                        elif addr.family == socket.AF_INET6:
                            ipv6_addr = addr.address

                    if interface in psutil.net_if_stats():
                        status = "Up" if psutil.net_if_stats()[interface].isup else "Down"

                    devices.append([len(devices) + 1, interface, mac_address, ip_address, ipv6_addr, status])

                headers = ["ID", "Name", "MAC Address", "IPv4 Address", "IPv6 Address", "Status"]
                table = tabulate.tabulate(devices, headers=headers, tablefmt="pretty", colalign=("left", "left", "left", "left", "left", "left"))
                print(table)
            except:
                raise

        def set(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Set device (interface)''', ["INTERFACE"]]
            try:
                old_iface = DeviceManager.IFACE
                DeviceManager.IFACE = str(args[0])
                print(f"[+] Device changed: '{old_iface}' -> '{DeviceManager.IFACE}'")
            except:
                raise

    class client:
        def list(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''List ClientManager.CLIENTS''', ["N/A"]]
            try:
                headers = [data for data in ClientManager.CLIENTS[list(ClientManager.CLIENTS.keys())[0]].__dict__ if not data.startswith("_")]
    
                rows = []
                for client in ClientManager.CLIENTS:
                    row = [str(ClientManager.CLIENTS[client].__dict__[data]) for data in headers]
                    rows.append(row)
                
                table = tabulate.tabulate(rows, headers=headers, tablefmt="pretty", colalign=("left",) * len(headers))
                print(table)
            except:
                raise

    class scan:
        def arp(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Scan devices in the network using ARP''', ["SCAN_RANGE", "TIMEOUT"]]
            ARPScanner.Scanner(str(args[0]), float(args[1]))

        def icmp(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Scan devices in the network using ICMP''', ["SCAN_RANGE", "TIMEOUT"]]
            ICMPScanner.Scanner(str(args[0]), float(args[1]))

        def tcp(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Scan devices in the network using TCP''', ["SCAN_RANGE", "TIMEOUT"]]
            TCPScanner.Scanner(str(args[0]), float(args[1]))

        def udp(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Scan devices in the network using UDP''', ["SCAN_RANGE", "TIMEOUT"]]
            UDPScanner.Scanner(str(args[0]), float(args[1]))

    class service:
        def list(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Print all available services''', ["N/A"]]
            services = []
            for name, instance in ServiceManager.Services.items():
                active = not getattr(instance, '_stop')
                status = "Activated"
                if active != True: status = "Deactivated"
                services.append([name, status])
            headers = ["Service", "Status"]
            table = tabulate.tabulate(services, headers=headers, tablefmt="pretty", colalign=("left", "left"))
            print(table)
        
        def start(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Activate service''', ["SERVICE"]]
            service = str(args[0])
            if service == "all":
                for name, instance in ServiceManager.Services.items():
                    instance.start()
                    print(f"[*] Service {name} has been started.")
            else:
                for name, instance in ServiceManager.Services.items():
                    if name == service and getattr(instance, "_stop", False) == True:
                        instance.start()
                        print(f"[*] Service {name} has been started.")
                        break

        def stop(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Deactivate service''', ["SERVICE"]]
            service = str(args[0])
            if service == "all":
                for name, instance in ServiceManager.Services.items():
                    instance.stop()
                    print(f"[*] Service {name} has been stopped.")
            else:
                for name, instance in ServiceManager.Services.items():
                    if name == service and getattr(instance, "_stop", False) == False:
                        instance.stop()
                        print(f"[*] Service {name} has been stopped.")
                        break

        def run(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Run service function''', ["SERVICE", "SERVICE_FUNCTION"]]
            func = str(args[0])
            target = str(args[1])
            print(f"[*] Executing service function: {func}.{target}")
            if not target.startswith("_"):
                for name, instance in ServiceManager.Services.items():
                    if name == func:
                        getattr(instance, target)()

        def help(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Show guide for the service functions''', ["SERVICE"]]
            service = str(args[0])
            for name, instance in ServiceManager.Services.items():
                temp_service_functions = []
                if service == name:
                    print(f"[Services.{name}]")
                    servname = name
                    for attr_name in dir(instance):
                        attr = getattr(instance, attr_name)
                        if callable(attr) and not attr_name.startswith("_"):
                            guide = attr.__doc__ if attr.__doc__ else "No description available."
                            temp_service_functions.append([servname, attr_name, f"{servname}.{attr_name}()", guide])

                    headers = ["Service", "Service Function", "Method Call", "Description"]
                    table = tabulate.tabulate(temp_service_functions, headers=headers, tablefmt="pretty", colalign=("left", "left", "left", "left"))
                    print(table)
                    break

    class proxy:
        def set(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Set proxy server''', ["SERVER", "PORT"]]
            try:
                PROXY_HOST = str(args[0])
                PROXY_PORT = int(args[1])
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, PROXY_HOST, PROXY_PORT, rdns=True)
                socket.socket = socks.socksocket
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("ifconfig.me", 80))
                s.sendall(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n")
                response = s.recv(4096).decode()
                s.close()

                ipv4_address = response.split("\r\n\r\n")[1].strip()
                print(f"Your IP address is (SOCKET): {ipv4_address}")
                print(f"Your IP address is (REQUEST): {requests.get('https://api.ipify.org').text}")
            except:
                raise

        def unset(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Unset proxy server''', ["N/A"]]
            try:
                socket.socket = ORIGIN_SOCKET
            except:
                raise

        def test(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Test proxy connection''', ["N/A"]]
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("ifconfig.me", 80))
                s.sendall(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n")
                response = s.recv(4096).decode()
                s.close()

                ipv4_address = response.split("\r\n\r\n")[1].strip()
                print(f"Your IP address is (SOCKET): {ipv4_address}")
                print(f"Your IP address is (REQUEST): {requests.get('https://api.ipify.org').text}")
            except:
                raise
            
    class var:
        def set(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Set local variable''', ["KEY", "VALUE"]]
            try:
                target = str(args[0])
                value = str(args[1])
                if target in SettingsManager.settings:
                    old = SettingsManager.settings[target]
                    SettingsManager.settings[target] = value
                    print(f"[+] Variable successfully changed: {old} --> {value}")
                elif not target in SettingsManager.settings:
                    print(f"[-] Variable change failed: variable not exists")
                else:
                    print(f"[-] Variable change failed: Unknown")
            except:
                raise
        def print(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''print local variable.\nType 'all' to see all local variables''', ["KEY"]]
            try:
                target = str(args[0])
                if target in SettingsManager.settings:
                    print(f"{target}{' ' * (32 - len(str(target)))}: {SettingsManager.settings[target]}")
                elif target == "all":
                    for key in SettingsManager.settings:
                        print(f"{key}{' ' * (32 - len(str(key)))}: {SettingsManager.settings[key]}")
                elif not target in SettingsManager.settings:
                    print(f"[-] Variable print failed: variable not exists")
                else:
                    print(f"[-] Variable print failed: Unknown")
            except:
                raise
        def reset(*args):
            if len(args) > 0 and args[0] == "help":
                return ['''Reset local variables''', ["N/A"]]
            SettingsManager.settings = SettingsManager.backup_settings

class Handler:
    def __init__(self, command):
        self.COMMAND = str(command)
        self.ObjectSplit = "."
        self.ArgumentsSplit = " "
        self.arguments = []
        self.object = Shell

    def execute(self):
        Type = self.COMMAND.split(self.ObjectSplit)[0]
        Func = self.COMMAND.split(self.ObjectSplit)[1].split(self.ArgumentsSplit)[0]
        
        try:
            arguments = shlex.split(self.COMMAND.split(self.ArgumentsSplit, 1)[1])
        except IndexError:
            arguments = []

        getattr(getattr(self.object, Type), Func)(*arguments)

# ----------------------------------------------------------------------------

if __name__ == "__main__":
    print(GLOBAL_TITLE)

    SOCKET_BACKUP = socket.socket

    DeviceManager.setup()
    print(f"[*] DeviceManager setup has been completed. [INTERFACE: {DeviceManager.IFACE} | MAC: {DeviceManager.DEVICE_MAC}]")

    OUIManager.setup()
    print(f"[*] OUIManager setup has been completed. [OUI DATABASE: {len(OUIManager.manufacturer)}]")

    ServiceManager.setup()
    print(f"[*] ServiceManager setup has been completed. [SERVICES: {len(ServiceManager.Services)}]")

    print("[*] Complete.")
    print()
    print()

    DeviceManager.setup()
    while True:
        try:
            DEVICE_MAC = DeviceManager.DEVICE_MAC
            INTERFACE = DeviceManager.IFACE
            command = str(input(f"A.R.G.U.S. v{Local_Version} [{DeviceManager.IFACE} ({DeviceManager.DEVICE_MAC})] > "))
            if command == "clear" or command == "cls": os.system("cls" if os.name == "nt" else "clear")
            elif command == "exit": break
            elif command == "": continue
            elif command == "disclaimer": print(GLOBAL_DISCLAIMER)
            elif command == "help":
                for Type in Shell.__dict__:
                    if not Type.startswith("__"):
                        print(f"[{Type}]")
                        commands = getattr(Shell, Type).__dict__
                        for func in commands:
                            if not func.startswith("__"):
                                help_object = getattr(getattr(Shell, Type), func)('help')
                                helptext = help_object[0]
                                help_args = help_object[1]

                                help_command = f"{f'{Type}.{func}':<30}"
                                if "\n" in helptext:
                                    helptext += ''.rjust(60-len(helptext.split("\n")[-1]), " ")
                                    helptext = str(helptext).replace("\n", f"\n{' ' * 30}")
                                else:
                                    helptext = f"{helptext:<60}"
                                print(f"{help_command}{helptext}{' '.join(help_args)}")
                        print("")
            else:
                obj = Handler(command=command)
                obj.execute()
                print("")
        except:
            print(f"{traceback.format_exc()}")