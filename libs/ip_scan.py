import socket
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from socket import gethostbyname, getservbyport, create_connection
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool
from libs import custom_logger
logger = custom_logger.logger
from pprint import pprint

def get_ip(domain):
    #get the ip address from the domain
    try :
        ip = gethostbyname(domain)
        return ip
    except:
        return None

# returns True if a connection can be made, False otherwise
def test_port_number(host, port):
    # create and configure the socket
    with socket(AF_INET, SOCK_STREAM) as sock:
        # set a timeout of a few seconds
        sock.settimeout(3)
        # connecting may fail
        try:
            # attempt to connect
            sock.connect((host, port))
            # a successful connection was made
            return True
        except:
            # ignore the failure
            return False
    
def port_scan(host, ports):
    open_ports = []
    logger.info(f'Scanning {host}...')
    # create the thread pool
    with ThreadPoolExecutor(len(ports)) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [host]*len(ports), ports)
        # report results in order
        for port,is_open in zip(ports,results):
            if is_open:
                open_ports.append(port)
    pprint(open_ports)
    return open_ports

def port_scan_with_thread_limit(host: str, ports:range, thread_number: int):
    #scan the host with the ports with a thread limit
    #return the open ports
    open_ports = []
    logger.info(f'Scanning {host}...')
    # create the thread pool
    with ThreadPoolExecutor(thread_number) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [host]*len(ports), ports)
        # report results in order
        for port,is_open in zip(ports,results):
            if is_open:
                logger.info(f'> {host}:{port} open')
                open_ports.append(port)
    return open_ports


def detect_service(ip, port):
    #detect the service from the ip address and the port
    #return the service
    try:
        #try to connect to the port
        create_connection((ip, port))
        #if the connection is successful, get the service
        service = getservbyport(port)
        return service
    except:
        return None

def detect_banner(ip, port):
    #detect the banner from the ip address and the port
    #return the banner
    try:
        #try to connect to the port
        s = create_connection((ip, port))
        #if the connection is successful, get the banner
        banner = s.recv(1024)
        return banner
    except:
        return None

def get_all_ip(subdomains: dict, domain :str):
    #for all subdomains ping them and retrive their ip address
    #return a dict with ip address as key and subdomains as value
    
    """
    subdomains = {
        "subdomain_withdomain": [],
        "subdomain_withoutdomain": [],
        "subdomain_with_redirect": []
    dict = {
            "ip1": {
                "subdomains"{
                    "subdomain_withdomain": [],
                    "subdomain_withoutdomain": [],
                    "subdomain_with_redirect": []
                }
                "ports": {
                    "port1": {
                        "state": "open",
                        "service": "http"
        }
    }
    """

    dict = {}
    for subdomain in subdomains["subdomain_withdomain"]:
        ip = get_ip(subdomain)
        if ip:
            if ip not in dict:
                dict[ip] = {
                    "subdomains": {
                        "subdomain_withdomain": [],
                        "subdomain_withoutdomain": [],
                        "subdomain_with_redirect": []
                    },
                    "ports": {}
                }
            dict[ip]["subdomains"]["subdomain_withdomain"].append(subdomain)
    for subdomain in subdomains["subdomain_withoutdomain"]:
        ip = get_ip(subdomain)
        if ip:
            if ip not in dict:
                dict[ip] = {
                    "subdomains": {
                        "subdomain_withdomain": [],
                        "subdomain_withoutdomain": [],
                        "subdomain_with_redirect": []
                    },
                    "ports": {}
                }
            dict[ip]["subdomains"]["subdomain_withoutdomain"].append(subdomain)
    for subdomain in subdomains["subdomain_with_redirect"]:
        ip = get_ip(subdomain)
        if ip:
            if ip not in dict:
                dict[ip] = {
                    "subdomains": {
                        "subdomain_withdomain": [],
                        "subdomain_withoutdomain": [],
                        "subdomain_with_redirect": []
                    },
                    "ports": {}
                }
            dict[ip]["subdomains"]["subdomain_with_redirect"].append(subdomain)
    return dict