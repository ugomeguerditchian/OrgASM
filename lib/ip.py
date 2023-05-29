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
        self.network = network
        self.ips = []

    def get_ip_from_network(self):
        # scan the network and retrieve the ip addresses
        # return the ip addresses
        if not "/" in self.network:
            self.network = self.network + "/24"
        # create the arp request
        arp = ARP(pdst=self.network)
        # create the ether broadcast packet
        # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # stack them
        packet = ether / arp
        # send the packet and receive a response
        result = srp(packet, timeout=3, verbose=0)[0]
        # a list of clients, we will fill this in the upcoming loop
        for sent, received in result:
            # for each response, append ip and mac address to `clients` list
            self.ips.append(received.psrc)


class ip:
    def __init__(self, ip: str, config: configuration):
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
        # ping the ip address using scapy
        # return True if the ip is up, False otherwise
        # create the arp request

        if self.ip.is_reserved:
            logger.error(f"{str(self.ip)} is reserved")
            return False
        s = self.handler.ping(self)
        if s:
            self.status = True
        else:
            self.status = False

    def port_scan(self, ports, thread_number):
        open_ports = []
        # create the thread pool
        with ThreadPoolExecutor(thread_number) as executor:
            # dispatch all tasks
            n = len(ports)
            results = list(
                tqdm(
                    executor.map(self.handler.connect, [str(self.ip)] * n, ports),
                    total=n,
                )
            )
            # wait for the tasks to complete
            for port, is_open in zip(ports, results):
                if is_open:
                    open_ports.append(port)
                    logger.info(f"Port {port} is open")
                    self.ports.update({port: {"service": ""}})

        return open_ports

    def check_filtered(self):
        target_ports = range(30000, 65535)
        start = time.time()
        self.port_scan(random.sample(target_ports, 1000), 1000)
        end = time.time()
        if end - start < 1.7:
            return True
        else:
            return False

    def ports_scan(self, ports: range, thread_number: int):
        # scan the host with the ports with a thread limit
        # return the open ports
        if self.handler.socks5_proxy != [] and self.type == "local":
            logger.warning("[!] Socks proxy is set but the ip is local")
            logger.warning("[!] Socks proxy will be ignored")
            logger.info("Resuming in 3 seconds...")
            time.sleep(3)
            tmp_socks5_proxy = self.handler.socks5_proxy
            self.handler.socks5_proxy = []

        if self.handler.socks5_proxy == []:
            logger.info(f"Checking if {self.ip} filtered...")
            if self.check_filtered():
                logger.warning(f"{self.ip} is filtered")
                return
            logger.info(f"{str(self.ip)} is not filtered")
        logger.info(f"Scanning {str(self.ip)}...")
        self.port_scan(ports, thread_number)
        if self.handler.socks5_proxy != [] and self.type == "local":
            self.handler.socks5_proxy = tmp_socks5_proxy

    def detect_service(self, port):
        # detect the service from the ip address and the port
        # return the service
        return {"service": self.handler.get_service(str(self.ip), port), "port": port}

    def try_access_web_port(self, port: str) -> bool:
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
        r = self.handler.get("http://" + str(self.ip), redirect=False)
        if r:
            fqdn = r.headers.get("Location")
            if fqdn:
                fqdn = fqdn.split("//")[1]
                if "/" in fqdn:
                    fqdn = fqdn.split("/")[0]
                # get the last part of the fqdn if it's a subdomain
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
        fqdns = self.handler.get_certificate_san(str(self.ip))
        if fqdns:
            for fqdn in fqdns:
                if not "." in fqdn:
                    fqdns.remove(fqdn)
                if "*" in fqdn:
                    fqdns.remove(fqdn)
                    fqdns.append(fqdn.replace("*.", ""))
        return fqdns
