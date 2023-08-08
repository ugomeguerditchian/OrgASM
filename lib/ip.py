from tqdm import tqdm

from concurrent.futures import ThreadPoolExecutor
import lib.custom_logger as custom_logger

logger = custom_logger.logger
from pprint import pprint
import os
import subprocess
import json
from datetime import datetime
from scapy.all import ARP, Ether, srp
import time
import random
from lib.handler import handler
import ipaddress
from lib.configuration import configuration


class network:
    def __init__(self, network: str):
        """
        Initializes a network object with the given network address.

        :param network: The network address to scan.
        """
        self.network = network
        self.ips = []

    def get_ip_from_network(self):
        """
        Scans the network and retrieves the IP addresses.

        :return: The IP addresses found on the network.
        """
        if not "/" in self.network:
            self.network = self.network + "/24"
        arp = ARP(pdst=self.network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            self.ips.append(received.psrc)


class ip:
    def __init__(self, ip: str, config: configuration):
        """
        Initializes an IP object with the given IP address and configuration.

        :param ip: The IP address to scan.
        :param config: The configuration object to use.
        """
        self.ip = ipaddress.ip_address(ip)
        self.config = config
        self.handler = config.handler
        self.status = False
        if self.ip.is_private:
            self.type = "local"
        else:
            self.type = "public"
        self.ports = {}

    def ping(self) -> bool:
        """
        Pings the IP address using Scapy.

        :return: True if the IP is up, False otherwise.
        """
        if self.ip.is_reserved:
            logger.error(f"{str(self.ip)} is reserved")
            return False
        s = self.handler.ping(self)
        if s:
            self.status = True
        else:
            self.status = False

    def port_scan(self, ports, thread_number):
        """
        Scans the host with the given ports with a thread limit.

        :param ports: The ports to scan.
        :param thread_number: The number of threads to use.
        :return: The open ports.
        """
        open_ports = []
        with ThreadPoolExecutor(thread_number) as executor:
            n = len(ports)
            results = list(
                tqdm(
                    executor.map(self.handler.connect, [str(self.ip)] * n, ports),
                    total=n,
                )
            )
            for port, is_open in zip(ports, results):
                if is_open:
                    open_ports.append(port)
                    logger.info(f"Port {port} is open")
                    self.ports.update({port: {"service": ""}})

        return open_ports

    def check_filtered(self):
        """
        Checks if the IP is filtered.

        :return: True if the IP is filtered, False otherwise.
        """
        target_ports = range(30000, 65535)
        start = time.time()
        self.port_scan(random.sample(target_ports, 1000), 1000)
        end = time.time()
        if end - start < 1.7:
            return True
        else:
            return False

    def ports_scan(self, ports: range, thread_number: int):
        """
        Scans the host with the given ports with a thread limit.

        :param ports: The ports to scan.
        :param thread_number: The number of threads to use.
        """
        if self.handler.socks5_proxy != [] and self.type == "local":
            logger.warning("[!] Socks proxy is set but the IP is local")
            logger.warning("[!] Socks proxy will be ignored")
            logger.info("Resuming in 3 seconds...")
            time.sleep(3)
            tmp_socks5_proxy = self.handler.socks5_proxy
            self.handler.socks5_proxy = []

        if self.handler.socks5_proxy == []:
            logger.info(f"Checking if {self.ip} is filtered...")
            if self.check_filtered():
                logger.warning(f"{self.ip} is filtered")
                return
            logger.info(f"{str(self.ip)} is not filtered")
        logger.info(f"Scanning {str(self.ip)}...")
        self.port_scan(ports, thread_number)
        if self.handler.socks5_proxy != [] and self.type == "local":
            self.handler.socks5_proxy = tmp_socks5_proxy

    def detect_service(self, port):
        """
        Detects the service from the IP address and the port.

        :param port: The port to scan.
        :return: The service.
        """
        return {"service": self.handler.get_service(str(self.ip), port), "port": port}

    def try_access_web_port(self, port: str) -> bool:
        """
        Tries to access the web port of the IP address.

        :param port: The port to scan.
        :return: True if the port is accessible, False otherwise.
        """
        try:
            self.handler.get(f"http://{str(self.ip)}:{port}")
            return True
        except:
            try:
                self.handler.get(f"https://{str(self.ip)}:{port}")
                return {"port": port}
            except:
                return {"port": port}

    def try_get_fqdn(self):
        """
        Tries to get the fully qualified domain name (FQDN) of the IP address.

        :return: The FQDN if found, None otherwise.
        """
        r = self.handler.get("http://" + str(self.ip), redirect=False)
        if r:
            fqdn = r.headers.get("Location")
            if fqdn:
                fqdn = fqdn.split("//")[1]
                if "/" in fqdn:
                    fqdn = fqdn.split("/")[0]
                fqdn = fqdn.split(".")[-2] + "." + fqdn.split(".")[-1]
                if not "." in fqdn:
                    return None
                return fqdn
            else:
                fqdn = self.handler.get_cert_fqdn(str(self.ip))
                if fqdn:
                    if not "." in fqdn:
                        return None
                    return fqdn
        else:
            return None

    def get_fqdns(self):
        """
        Gets the fully qualified domain names (FQDNs) of the IP address.

        :return: The FQDNs if found, None otherwise.
        """
        fqdns = self.handler.get_certificate_san(str(self.ip))
        if fqdns:
            for fqdn in fqdns:
                if not "." in fqdn:
                    fqdns.remove(fqdn)
                if "*" in fqdn:
                    fqdns.remove(fqdn)
                    fqdns.append(fqdn.replace("*.", ""))
        return fqdns
