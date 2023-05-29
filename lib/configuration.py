import random
import scapy
from scapy.all import *
from scapy.contrib import socks
from scapy.layers.inet import ICMP
import socket
import socks
import os
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import urllib3
from urllib3 import Timeout
from urllib3.contrib.socks import SOCKSProxyManager
import lib.custom_logger as custom_logger
import lib.ip as ip_lib
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
import json
import yaml
import requests
import lib.custom_logger as custom_logger

logger = custom_logger.logger


class configuration:
    """Configuration is ./congiuration.yaml"""

    def __init__(self):
        try:
            self.config = yaml.load(
                open("configuration.yaml", "r"), Loader=yaml.FullLoader
            )
        except Exception as e:
            logger.error(f"[X] Error with configuration.yaml : {e}")
            exit()

        self.http_proxy = []
        self.https_proxy = []
        self.socks_proxy = []
        try:
            self.proxy_file = None
            self.header = self.config["Handler"]["header"]
            self.ip_get_fqdn = self.config["IP"]["try_get_fqdn"]
            self.api_trough_proxy = self.config["API"]["trough_proxy"]
            self.ip_trough_proxy = self.config["IP"]["trough_proxy"]
            self.find_subs = self.config["FQDN"]["find_subs"]
            self.get_fqdn_trough_proxy = self.config["FQDN"]["get_fqdn_trough_proxy"]
            self.get_proxy_worker = self.config["Proxy"]["get_workers"]
            self.api_max_workers = self.config["API"]["max_workers"]
            self.get_fqdn_cert = self.config["FQDN"]["get_from_cert"]
            if self.get_fqdn_cert:
                logger.warning(
                    "[!] Warning : Direct connection will be used to get fqdn from cert"
                )
            self.load()
        except Exception as e:
            logger.error(f"[X] Error with configuration.yaml : {e}")
            exit()

    def load(self):
        if self.config["Proxy"]["file"]:
            if os.path.isfile(self.config["Proxy"]["file"]):
                self.proxy_file = self.config["proxy"]["file"]
                if self.config["Proxy"]["only_file"]:
                    self.https_proxy = []
                    self.http_proxy = []
                    self.socks_proxy = []
                    for line in open(self.proxy_file, "r").readlines():
                        proxy, type = line.split("|")
                        if type == "http":
                            self.http_proxy.append(proxy)
                        elif type == "https":
                            self.https_proxy.append(proxy)
                        elif type == "socks":
                            self.socks_proxy.append(proxy)
                else:
                    for line in open(self.proxy_file, "r").readlines():
                        proxy, type = line.split("|")
                        if type == "http":
                            self.http_proxy.append(proxy)
                        elif type == "https":
                            self.https_proxy.append(proxy)
                        elif type == "socks":
                            self.socks_proxy.append(proxy)
            else:
                logger.error("[X] Error: Proxy file not found")
                exit()
        else:
            if self.config["Proxy"]["activate"]:
                logger.info("[*] Info: Proxy activated")
                # logger.info("[*] Testing proxy...")
                for link, type in self.config["Proxy"]["links"].items():
                    for line in requests.get(link).text.splitlines():
                        if type == "http":
                            self.http_proxy.append(line)
                        elif type == "https":
                            self.https_proxy.append(line)
                        elif type == "socks":
                            self.socks_proxy.append(line)
                # self.check_proxy()

    def is_in_scope(self, to_test: str, mode: str):
        """Check if a fqdn or ip is in scope"""
        scope = []
        if self.config["SCOPE"][mode]["file"]:
            if os.path.isfile(self.config["SCOPE"][mode]["file"]):
                for line in open(self.config["SCOPE"][mode]["file"], "r").readlines():
                    scope.append(line.replace("\n", ""))
            else:
                logger.error("[X] Error: Scope file not found")
                exit()
        if self.config["SCOPE"][mode]["list"]:
            for line in self.config["SCOPE"][mode]["list"]:
                scope.append(line)
        for i in scope:
            if i == to_test:
                return True
            else:
                return False
        if self.config["SCOPE"][mode]["regex"]:
            # example : regex: ["r'tesla'"]
            for regex in self.config["SCOPE"][mode]["regex"]:
                # convert it to r
                regex = r"{}".format(regex)
                if re.search(regex, to_test):
                    return True
                else:
                    return False
        if len(scope) == 0:
            return True

    def is_there_scope(self):
        mode = ["IPs", "FQDNs"]
        there_is = False
        for i in mode:
            if (
                self.config["SCOPE"][i]["file"]
                or self.config["SCOPE"][i]["list"]
                or self.config["SCOPE"][i]["regex"]
            ):
                there_is = True
        return there_is

    def get_github_proxy(self, links: dict):
        """Get a proxy from github.com
        Format must be ip:port for each line
        links{
        link:type (http, https, socks)
        }
        """
        for link, type in links.items():
            try:
                r = requests.get(link)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if type == "http":
                            self.http_proxy.append(line)
                        elif type == "https":
                            self.https_proxy.append(line)
                        elif type == "socks":
                            self.socks_proxy.append(line)
                else:
                    logger.warning(
                        "[!] Warning : {} returned status code {}".format(
                            link, r.status_code
                        )
                    )
            except:
                logger.warning("[!] Warning : {} returned an error".format(link))
        # check if proxy are working

    def check_proxy(self):
        # open proxy_test.txt and add all line to a list
        test_urls = open("proxy_test.txt", "r").readlines()
        for i in range(len(test_urls)):
            test_urls[i] = test_urls[i].replace("\n", "")
        """Check if all proxy are working"""
        with ThreadPoolExecutor(
            # max_workers=self.config["Proxy"]["testing_worker"]~
            max_workers=1000
        ) as executor:
            # for proxy in self.http_proxy:
            #     choice = random.choice(test_urls)
            #     executor.submit(self.check_http_proxy, proxy, choice)
            for proxy in self.https_proxy:
                choice = random.choice(test_urls)
                executor.submit(self.check_https_proxy, proxy, choice)
            for proxy in self.socks_proxy:
                choice = random.choice(test_urls)
                executor.submit(self.check_socks_proxy, proxy, choice)
        logger.info("[*] Proxy checked")
        logger.info(
            "[*] Total proxy: {}".format(
                len(self.http_proxy) + len(self.https_proxy) + len(self.socks_proxy)
            )
        )
        logger.info("[*] Http proxy: {}".format(len(self.http_proxy)))
        logger.info("[*] Https proxy: {}".format(len(self.https_proxy)))
        logger.info("[*] Socks proxy: {}".format(len(self.socks_proxy)))

    def check_http_proxy(self, proxy: str, url: str):
        """Check if a http proxy is working"""
        # use urllib3
        try:
            r = urllib3.ProxyManager("http://" + proxy, timeout=3.0)
            r.request("GET", "http://" + url)
            if r.status_code != 200:
                self.http_proxy.remove(proxy)
            r.close()
        except:
            self.http_proxy.remove(proxy)

    def check_https_proxy(self, proxy: str, url: str):
        """Check if a https proxy is working"""
        try:
            r = urllib3.ProxyManager("https://" + proxy)
            r.request("GET", "https://" + url, timeout=3.0)
            if r.status_code != 200:
                self.https_proxy.remove(proxy)
            r.close()
        except:
            self.https_proxy.remove(proxy)

    def check_socks_proxy(self, proxy: str, url: str):
        """Check if a socks proxy is working"""
        try:
            r = urllib3.ProxyManager("socks5://" + proxy, timeout=3.0)
            r.request("GET", "https://" + url)
            if r.status_code != 200:
                self.socks_proxy.remove(proxy)
            r.close()
        except:
            self.socks_proxy.remove(proxy)
