import random
import scapy
from scapy.all import *
from scapy.contrib import socks
from scapy.layers.inet import ICMP
import socket
import socks
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import urllib3
from urllib3 import Timeout
from urllib3.contrib.socks import SOCKSProxyManager
import lib.custom_logger as custom_logger
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import lib.configuration as configuration


logger = custom_logger.logger

list_to_raise = [
    "API count exceeded - Increase Quota with Membership",
    "429 Too Many Requests",
]


class handler:
    """Generic class for handling GET and socket connection requests, can be linked to a proxy"""

    def __init__(self, config: configuration):
        """
        Initializes the handler object with the given configuration.

        :param config: A configuration object.
        """
        self.http_proxy = config.http_proxy
        self.https_proxy = config.https_proxy
        self.socks5_proxy = config.socks_proxy
        self.get_proxy_worker = config.get_proxy_worker

    def there_is_proxy(self):
        """
        Checks if there is a proxy available.

        :return: True if there is a proxy available, False otherwise.
        """
        if self.http_proxy == [] and self.https_proxy == [] and self.socks5_proxy == []:
            return False
        else:
            return True

    def getter(
        self, url: str, redirect: bool, until_ok: bool, params=None, headers=None
    ):
        """
        Sends a GET request using a random proxy.

        :param url: The URL to send the request to.
        :param redirect: Whether or not to follow redirects.
        :param until_ok: Whether or not to keep trying until a successful response is received.
        :param params: Optional parameters to include in the request.
        :param headers: Optional headers to include in the request.

        :return: A response object if the request was successful, None otherwise.
        """
        types = ["http", "https", "socks5"]
        while True:
            rand_type = random.choice(types)
            cat = getattr(self, f"{rand_type}_proxy")
            if cat != []:
                rand_proxy = rand_type + "://" + random.choice(cat)
                break
        timeout = Timeout(connect=3.0, read=3.0)
        if headers == None:
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            }
        try:
            if rand_type == "socks5":
                r = SOCKSProxyManager(rand_proxy).request(
                    "GET", url, headers=headers, timeout=timeout, redirect=redirect
                )
                if r.status == 200:
                    if r._body.decode("utf-8") in list_to_raise:
                        return None
                    return r
                else:
                    if until_ok:
                        self.socks5_proxy.remove(rand_proxy.split("://")[1])
                    return None
            r = urllib3.ProxyManager(rand_proxy, timeout=timeout).request(
                "GET", url, headers=headers, timeout=timeout, redirect=redirect
            )
            if r.status == 200:
                if r._body.decode("utf-8") in list_to_raise:
                    return None
                return r
            else:
                if rand_type == "http" and until_ok:
                    self.http_proxy.remove(rand_proxy.split("://")[1])
                elif rand_type == "https" and until_ok:
                    self.https_proxy.remove(rand_proxy.split("://")[1])
                return None
        except:
            if rand_type == "http" and until_ok:
                self.http_proxy.remove(rand_proxy.split("://")[1])
            elif rand_type == "https" and until_ok:
                self.https_proxy.remove(rand_proxy.split("://")[1])
            elif rand_type == "socks5" and until_ok:
                self.socks5_proxy.remove(rand_proxy.split("://")[1])
            return None

    def get(
        self,
        url: str,
        params=None,
        headers=None,
        redirect: bool = True,
        until_ok: bool = False,
    ):
        """
        Sends a GET request using a random proxy.

        :param url: The URL to send the request to.
        :param params: Optional parameters to include in the request.
        :param headers: Optional headers to include in the request.
        :param redirect: Whether or not to follow redirects.
        :param until_ok: Whether or not to keep trying until a successful response is received.

        :return: A response object if the request was successful, None otherwise.
        """
        # launch a pool of threads, when one is done, return the response and kill the others
        pool = []
        retry_strategy = urllib3.Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429],
            respect_retry_after_header=False,
        )
        http = urllib3.PoolManager(retries=retry_strategy)
        while True:
            if not self.there_is_proxy():
                try:
                    data = http.request(
                        "GET", url, headers=headers, timeout=3.0, redirect=redirect
                    )
                except:
                    data = None
                return data
            else:
                with ThreadPoolExecutor(max_workers=self.get_proxy_worker) as executor:
                    for i in range(self.get_proxy_worker):
                        pool.append(
                            executor.submit(
                                self.getter, url, redirect, until_ok, headers=headers
                            )
                        )
                    done, not_done = wait(pool, return_when=FIRST_COMPLETED)
                    for future in not_done:
                        future.cancel()
                    for future in done:
                        try:
                            if future.result() != None:
                                return future.result()
                            else:
                                pass
                        except:
                            pass
                    if not until_ok:
                        if future.result() == None:
                            logger.warning(
                                f"No proxy available in this pool as responded for {url}, trying without..."
                            )
                            try:
                                # don't use proxy
                                data = http.request(
                                    "GET",
                                    url,
                                    headers=headers,
                                    timeout=3.0,
                                    redirect=redirect,
                                )
                            except:
                                data = None
                            return data

    def connect(self, ip: str, port: int):
        """Connect to the given IP address and port using a random SOCKS5 proxy if available.

        :param ip: The IP address to connect to.
        :type ip: str
        :param port: The port to connect to.
        :type port: int
        :return: True if the connection was successful, False otherwise.
        :rtype: bool
        """
        # Function to connect to the given IP address and port using a random SOCKS5 proxy if available.
        if self.socks5_proxy == []:
            s = socket.socket()
            s.settimeout(3)
            try:
                s.connect((ip, port))
                s.close()
                return True
            except:
                return False
        else:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, random.choice(self.socks5_proxy))
            s.settimeout(3)
            try:
                s.connect((ip, port))
                s.close()
                # remove the proxy from s
                s.set_proxy()
                return True
            except:
                s.set_proxy()
                return False

    def ping(self, this_ip):
        """Ping the given IP address using Scapy and SOCKS5 if available.

        :param this_ip: The IP address to ping.
        :type this_ip: lib.ip.IP
        :return: True if the IP address is up, False otherwise.
        :rtype: bool
        """
        # Function to ping the given IP address using Scapy and SOCKS5 if available.
        import lib.ip as ip

        logger.info(f"Checking if {str(this_ip.ip)} is up...")
        icmp = ICMP()
        ip_packet = scapy.layers.inet.IP(dst=str(this_ip.ip)) / icmp
        if self.socks5_proxy == []:
            result = sr(ip_packet, timeout=3, verbose=0)[0]
        else:
            rand_proxy = random.choice(self.socks5_proxy)
            socks.set_default_proxy(socks.SOCKS5, rand_proxy)
            socket.socket = socks.socksocket
            result = sr(ip_packet, timeout=3, verbose=0)[0]
            # remove the proxy from socket
            socks.set_default_proxy()
        is_alive = False
        for sent, received in result:
            if received:
                is_alive = True
            else:
                is_alive = False
        if (
            not is_alive
            and this_ip.port_scan(random.sample(range(1, 1000), 800), 2000) == []
        ):
            logger.warning(f"{str(this_ip.ip)} is down")
            return False
        else:
            logger.info(f"{str(this_ip.ip)} is up")
            return True

    def get_cert_fqdn(self, hostname: str):
        """Get the fully qualified domain name (FQDN) of the given hostname using the certificate.

        :param hostname: The hostname to get the FQDN for.
        :type hostname: str
        :return: The FQDN of the hostname if it can be obtained from the certificate, None otherwise.
        :rtype: str or None
        """
        # Function to get the fully qualified domain name (FQDN) of the given hostname using the certificate.
        try:
            if self.socks5_proxy == []:
                cert = ssl.get_server_certificate((hostname, 443))
                cert = ssl.PEM_cert_to_DER_cert(
                    cert
                )  # Convert certificate to DER format
                begin = (
                    cert.rfind(b"\x06\x03\x55\x04\x03") + 7
                )  # Find the last occurrence of this byte string indicating the CN, add 7 bytes to start point to account for length of byte string and padding
                end = (
                    begin + cert[begin - 1]
                )  # Set endpoint to start point + the length of the CN
                fqdn = cert[begin:end].decode("utf-8")  # Decode the CN
                if fqdn.startswith("*."):
                    fqdn = fqdn[2:]
                return fqdn
            else:
                rand_proxy = random.choice(self.socks5_proxy)
                socks.set_default_proxy(socks.SOCKS5, rand_proxy)
                socket.socket = socks.socksocket
                cert = ssl.get_server_certificate((hostname, 443))
                cert = ssl.PEM_cert_to_DER_cert(cert)
                begin = cert.rfind(b"\x06\x03\x55\x04\x03") + 7
                end = begin + cert[begin - 1]
                fqdn = cert[begin:end].decode("utf-8")
                if fqdn.startswith("*."):
                    fqdn = fqdn[2:]
                if fqdn.split(".")[-1].isnumeric():
                    return None
                socks.set_default_proxy()
                return fqdn
        except Exception as e:
            socks.set_default_proxy()
            logger.error(f"Unable to get the FQDN of {hostname} from the certificate")
            return None

    def connect_and_send(self, ip: str, port: int) -> str:
        """
        Connect to a given IP address and port and send a request.

        :param ip: The IP address to connect to.
        :type ip: str
        :param port: The port to connect to.
        :type port: int

        :return: The response from the server.
        :rtype: str
        """
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.1\r\n\r\n")
            data = s.recv(1024)
            s.close()
            return data.decode("utf-8")
        except Exception as e:
            logger.error(f"Impossible to get the service on {ip}:{port}")
            return None

    def get_certificate_san(self, domain: str) -> str:
        """
        Get the Subject Alternative Names (SAN) of a given domain.

        :param domain: The domain to get the SAN for.
        :type domain: str

        :return: The SAN of the given domain.
        :rtype: str
        """
        try:
            ip = socket.gethostbyname(domain)
            return self.connect_and_send(ip, 443)
        except Exception as e:
            logger.error(f"Impossible to get the SAN for {domain}")
            return None

    def get_service(self, ip: str, port: int) -> str:
        """
        Get the services running on a given IP address and port.

        :param ip: The IP address to get the services for.
        :type ip: str
        :param port: The port to get the services for.
        :type port: int

        :return: The services running on the given IP address and port.
        :rtype: str
        """
        try:
            return self.connect_and_send(ip, port)
        except Exception as e:
            logger.error(f"Impossible to get the service on {ip}:{port}")
            return None

    def remove_proxys(self) -> dict:
        """
        Remove all the proxy configurations.

        :return: A dictionary containing the old proxy configurations.
        :rtype: dict
        """
        olds = {}
        olds["http"] = self.http_proxy
        olds["https"] = self.https_proxy
        olds["socks5"] = self.socks5_proxy
        self.http_proxy = []
        self.https_proxy = []
        self.socks5_proxy = []
        return olds

    def add_proxys(self, olds: dict):
        """
        Add the old proxy configurations.

        :param olds: The old proxy configurations to add.
        :type olds: dict
        """
        self.http_proxy = olds["http"]
        self.https_proxy = olds["https"]
        self.socks5_proxy = olds["socks5"]
