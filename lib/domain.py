from lib.handler import handler
from dns import resolver
import lib.custom_logger as custom_logger
import api.global_parser as global_parser
from lib.configuration import configuration

logger = custom_logger.logger


class domain:
    def __init__(self, name: str, config: configuration):
        self.name = name
        self.config = config
        self.subdomains = []
        self.ip = self.get_ip()
        self.handler = self.config.handler
        self.trough_proxy = config.api_trough_proxy

    def get_subs(self, ip_trough_proxy: bool = False):
        # get all the subdomains of the domain
        changed = False
        if not self.trough_proxy and self.handler.there_is_proxy():
            logger.info("[*] Disabling proxy for requesting API")
            changed = True
            olds = self.handler.remove_proxys()
        logger.info(f"[*] Getting subdomains for {self.name}")

        self.subdomains += global_parser.main(self.name, self.config)
        if changed:
            logger.info("[*] Re-enabling proxy")
            self.handler.add_proxys(olds)
        # get the subdomains from bufferover
        # self.subdomains += bufferover_parser(self.name)
        # # get the subdomains from threatcrowd
        # self.subdomains += threatcrowd_parser(self.name)
        # # get the subdomains from threatminer
        # self.subdomains += threatminer_parser(self.name)
        # # get the subdomains from virustotal
        # self.subdomains += virustotal_parser(self.name)
        # # get the subdomains from anubis
        # self.subdomains += anubis_parser(self.name)
        # # get the subdomains from securitytrails
        # self.subdomains += securitytrails_parser(self.name)
        # # get the subdomains from certspotter
        # self.subdomains += certspotter_parser(self.name)
        # # get the subdomains from riddler
        # self.subdomains += riddler_parser(self.name)
        # # get the subdomains from sublist3r
        # self.subdomains += sublist3r_parser(self.name)
        # # get the subdomains from subfinder
        # self.subdomains += subfinder_parser(self.name)
        # # get the subdomains from amass
        # self.subdomains += amass_parser(self.name)
        # # get the subdomains from assetfinder
        # self.subdomains += assetfinder_parser(self.name)
        # # get the subdomains from findomain
        # self.subdomains += findomain_parser(self.name)
        # # get the subdomains from dnsdumpster
        # self.subdomains += dnsdumpster_parser(self.name)
        # # get the subdomains from spyse
        # self.subdomains += spyse_parser(self.name)
        # # get the subdomains from rapiddns
        # self.subdomains += rapiddns_parser(self.name)
        # # get the subdomains from threatbook
        # self.subdomains += threatbook_parser(self.name)
        # # get the subdomains from dnsbuffer
        # self.subdomains += dnsbuffer_parser(self.name)
        # # get the subdomains from threatminer
        # self.subdomains += threatminer_parser(self.name)
        changed = False
        if not ip_trough_proxy and self.handler.there_is_proxy():
            logger.info("[*] Deactivating proxy")
            olds = self.handler.remove_proxys()
            changed = True
        if self.config.get_fqdn_cert:
            logger.info("[*] Getting fqdns trough certificate for {}".format(self.name))
            with_cert = self.handler.get_certificate_san(self.name)
            if with_cert:
                self.subdomains += with_cert
            with_cert = self.handler.get_cert_fqdn(self.name)
            if with_cert:
                self.subdomains += [with_cert]
        if changed:
            logger.info("[*] Re-enabling proxy")
            self.handler.add_proxys(olds)
        return self.subdomains

    def get_ip(self):
        # get the ip address from the domain by using dns resolver
        try:
            ip = resolver.resolve(self.name, "A")
            return ip[0].to_text()
        except:
            return "Dead"
