from lib.handler import handler
from dns import resolver
import lib.custom_logger as custom_logger
import api.global_parser as global_parser
from lib.configuration import configuration
import re

logger = custom_logger.logger


def valid_fqdn(fqdn: str) -> bool:
    fqdn_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )
    if fqdn_regex.match(fqdn) is None:
        return False
    else:
        if fqdn != "\\r" and "." in fqdn:
            return True


class domain:
    def __init__(self, name: str, config: configuration):
        """
        Initializes a domain object with a given name and configuration.

        :param name: The name of the domain.
        :param config: The configuration object to use.
        """
        self.name = name
        self.config = config
        self.subdomains = []
        if valid_fqdn(self.name):
            self.ip = self.get_ip()
        else:
            self.ip = "Invalid"
        self.handler = self.config.handler
        self.trough_proxy = config.api_trough_proxy

    def get_subs(self, ip_trough_proxy: bool = False):
        """
        Gets all the subdomains of the domain.

        :param ip_trough_proxy: Whether to get the IP through a proxy.
        :return: A list of subdomains.
        """
        # get all the subdomains of the domain
        changed = False
        if not self.trough_proxy and self.handler.there_is_proxy():
            logger.info("[*] Disabling proxy for requesting API")
            changed = True
            olds = self.handler.remove_proxys()
        logger.info(f"[*] Getting subdomains for {self.name}")
        self.subdomains += [
            subdomain
            for subdomain in global_parser.main(self.name, self.config)
            if subdomain and valid_fqdn(subdomain)
        ]
        if changed:
            logger.info("[*] Re-enabling proxy")
            self.handler.add_proxys(olds)
        changed = False
        if not ip_trough_proxy and self.handler.there_is_proxy():
            logger.info("[*] Deactivating proxy")
            olds = self.handler.remove_proxys()
            changed = True
        if self.config.get_fqdn_cert:
            logger.info("[*] Getting fqdns trough certificate for {}".format(self.name))
            with_cert = self.handler.get_certificate_san(self.name)
            if with_cert and valid_fqdn(with_cert) and with_cert not in self.subdomains:
                self.subdomains += with_cert
            with_cert = self.handler.get_cert_fqdn(self.name)
            if with_cert and valid_fqdn(with_cert) and with_cert not in self.subdomains:
                self.subdomains += [with_cert]
        if changed:
            logger.info("[*] Re-enabling proxy")
            self.handler.add_proxys(olds)
        return self.subdomains

    def get_ip(self):
        """
        Gets the IP address from the domain by using DNS resolver.

        :return: The IP address of the domain.
        """
        try:
            ip = resolver.resolve(self.name, "A")
            return ip[0].to_text()
        except:
            return "Dead"
