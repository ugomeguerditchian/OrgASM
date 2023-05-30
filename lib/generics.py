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
from lib.handler import handler
from lib.result import result
from lib.domain import domain
from lib.configuration import configuration
from tqdm import tqdm

import requests
import re

logger = custom_logger.logger


def clear_screen():
    """Clear the screen"""
    os.system("cls" if os.name == "nt" else "clear")


def fqdn_scanner(main_fqdn: str, config: configuration, res: result, recursive: int = 0):
    logger.info("[*] Scanning fqdn {}".format(main_fqdn))
    main_domain = domain(main_fqdn, config)
    if main_domain.ip == "Dead":
        res.add_dead(main_domain.name)
    else:
        this_ip = ip_lib.ip(main_domain.ip, config)
        res.add_fqdn(this_ip, main_domain.name)
    subs = main_domain.get_subs(config.ip_trough_proxy)
    # remove duplicates
    subs = list(dict.fromkeys(subs))
    futures_scope = {}
    if config.is_there_scope():
        with ThreadPoolExecutor(max_workers=config.api_max_workers) as executor:
            for fqdn in subs:
                futures_scope[fqdn] = executor.submit(
                    config.is_in_scope, fqdn, mode="FQDNs"
                )
        for fqdn in subs:
            futures_scope[fqdn] = futures_scope[fqdn].result()

    with ThreadPoolExecutor(max_workers=config.api_max_workers) as executor:
        futures_domain = {fqdn: executor.submit(domain, fqdn, config) for fqdn in subs}

    for fqdn in tqdm(subs, desc="Processing subdomains", ncols=100):
        if fqdn == "localhost" or config.is_there_scope() and not futures_scope[fqdn]:
            continue
        sub_domain = futures_domain[fqdn].result()
        if sub_domain.ip == "Dead":
            res.add_dead(sub_domain.name)
        else:
            if not res.check_if_fqdn_in_res(sub_domain.name):
                if not res.check_if_ip_in_res(sub_domain.ip):
                    this_ip = ip_lib.ip(sub_domain.ip, config)
                else:
                    this_ip = res.get_ip_in_res(sub_domain.ip)
                res.add_fqdn(this_ip, sub_domain.name)

    if recursive > 0:
        res.status()
        logger.info("[*] Recursive scan")
        subs = []
        old_subs = [main_fqdn]
        for i in range(recursive):
            with ThreadPoolExecutor(max_workers=config.api_max_workers) as executor:
                futures_get_subs = []
                futures_domain_recursive = {}
                for ip in res.result:
                    if config.is_there_scope() and not config.is_in_scope(
                        str(ip.ip), mode="IPs"
                    ):
                        continue
                    for fqdn in res.result[ip]["fqdns"]:
                        if (
                            fqdn not in old_subs
                            or config.is_there_scope()
                            and config.is_in_scope(fqdn, mode="FQDNs")
                        ):
                            old_subs.append(fqdn)
                            logger.info(f"[*] Scanning subdomain {fqdn}")
                            sub_domain_future = executor.submit(domain, fqdn, config)
                            futures_domain_recursive[fqdn] = sub_domain_future
                            futures_get_subs.append(
                                executor.submit(sub_domain_future.result().get_subs, config.ip_trough_proxy)
                            )
                logger.info(
                    "[*] Waiting for {} threads to finish to getting subs".format(
                        len(futures_get_subs)
                    )
                )
                for future in futures_get_subs:
                    subs += future.result()
                logger.info(
                    "[*] {} subs found (may contain duplicates)".format(len(subs))
                )
                # remove duplicates
                subs = list(dict.fromkeys(subs))
                for fqdn in tqdm(subs, desc="Processing subdomains", ncols=100):
                    if fqdn == "localhost" or config.is_there_scope() and not futures_scope[fqdn] or fqdn not in futures_domain_recursive:
                        continue
                    sub_domain = futures_domain_recursive[fqdn].result()
                    if sub_domain.ip == "Dead":
                        res.add_dead(sub_domain.name)
                    else:
                        if not res.check_if_fqdn_in_res(sub_domain.name):
                            if not res.check_if_ip_in_res(sub_domain.ip):
                                this_ip = ip_lib.ip(sub_domain.ip, config)
                            else:
                                this_ip = res.get_ip_in_res(sub_domain.ip)
                            res.add_fqdn(this_ip, sub_domain.name)

            logger.info("[*] Recursive {} finished".format(i + 1))
            res.status()



def ip_scanner(ip: str, config: configuration, res: result, recursive: int = 0):
    ip_obj = ip_lib.ip(ip, config)
    res.add_ip(ip_obj)
    if config.ip_get_fqdn:
        if not config.get_fqdn_trough_proxy and config.handler.there_is_proxy():
            logger.info("[*] Deactivating proxy")
            old_handler = ip_obj.handler
            ip_obj.handler = handler(config)
            logger.info(f"[*] Getting FQDN for {str(ip_obj.ip)}")
            fqdn = ip_obj.try_get_fqdn()
            if not fqdn:
                fqdn = ip_obj.get_fqdns()
                if fqdn:
                    fqdn = fqdn[0]
            logger.info("[*] Reactivating proxy")
            ip_obj.handler = old_handler
        else:
            logger.info(f"[*] Getting FQDN for {str(ip_obj.ip)}")
            fqdn = ip_obj.try_get_fqdn()
            if not fqdn:
                fqdn = ip_obj.get_fqdns()
                if fqdn:
                    fqdn = fqdn[0]

        if fqdn and config.is_there_scope() and config.is_in_scope(fqdn, mode="FQDNs"):
            res.add_fqdn(ip_obj, fqdn)
            if config.find_subs:
                logger.info("[*] Finding subdomains")
                fqdn_scanner(fqdn, config, res, recursive)


def check_update():
    logger.info("Checking for update...")
    try:
        with open("manifest", "r") as f:
            version = f.read()
        url = (
            f"https://raw.githubusercontent.com/ugomeguerditchian/OrgASM/main/manifest"
        )
        response = requests.get(url).text
        if response == version:
            logger.info("You are up to date")
        else:
            logger.warning(
                "Update available, please download the new version on https://github.com/ugomeguerditchian/OrgASM"
            )
            logger.info("Resume in 3 seconds...")
            time.sleep(3)
    except Exception as e:
        logger.error("Impossible to check for update")
