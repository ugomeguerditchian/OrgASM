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
import os
import subprocess
import json
from datetime import datetime

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

def check_if_nuclei_installed() -> bool:
    #check if nuclei is installed by doing nuclei -h
    #return True if installed, False otherwise
    #use subprocess to run the command and don't show the output
    try:
        subprocess.run(["nuclei", "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def nuclei_scan(hosts: list, domain: str, vulnconf: str) -> dict:
    #scan the hosts with nuclei
    #return the results
    #check if nuclei is installed
    logger.info("Checking if nuclei is installed...")
    if not check_if_nuclei_installed():
        logger.error("Nuclei is not installed")
        return None
    else :
        logger.info("Nuclei is installed")

    #create nuclei folder in project folder
    if not os.path.exists("nuclei"):
        os.mkdir("nuclei")
    
    #create a folder for the domain
    if not os.path.exists(f"nuclei/{domain}"):
        os.mkdir(f"nuclei/{domain}")
    
    #create a hosts.txt with one host per line
    with open(f"nuclei/{domain}/hosts.txt", "w") as f:
        for host in hosts:
            f.write(f"{host}\r")
        f.close()
        #parse the file and delete if line is empty
        with open(f"nuclei/{domain}/hosts.txt", "r") as f:
            lines = f.readlines()
            f.close()
        with open(f"nuclei/{domain}/hosts.txt", "w") as f:
            for line in lines:
                if line.strip("\r") != "":
                    f.write(line)
            f.close()
    
    #update nuclei don't show the output
    logger.info("Updating nuclei")
    subprocess.run(["nuclei", "-update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #update nuclei templates
    logger.info("Updating nuclei templates")
    subprocess.run(["nuclei", "-ut"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    #run nuclei and save the results in a json file
    actual_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if vulnconf != "":
        logger.info("Running nuclei with config file")
        os.system(f"nuclei -l nuclei/{domain}/hosts.txt -config {vulnconf} -json -o nuclei/{domain}/results.json")
    else :
        os.system(f"nuclei -l nuclei/{domain}/hosts.txt -json -o nuclei/{domain}/results_{actual_time}.json")
    #read the output
    with open(f"nuclei/{domain}/results_{actual_time}.json", "r") as f:
        if f.read() == "":
            return None
        #each line is a json
        f.seek(0)
        results = []
        for line in f:
            results.append(json.loads(line))
        f.close()
    return results

def run_parse_nuclei(ip_dict: dict, domain: str, mode :str, vulnconf :str) -> dict:
    logger.info("Running nuclei scan...")
    hosts_list = []
    for ip in ip_dict:
        if (mode == "W" and ip_dict[ip]["subdomains"]["subdomain_withdomain"] != []) or (mode == "WR" and ip_dict[ip]["subdomains"]["subdomain_withdomain"] != [] or ip_dict[ip]["subdomains"]["subdomain_with_redirect"] != []) or (mode =="A"):
            hosts_list.append(ip)
        if mode == "W" or mode == "WR" or mode == "A":
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_withdomain"]:
                hosts_list.append("https://"+subdomain)
        if mode == "WR" or mode == "A":
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_with_redirect"]:
                hosts_list.append("https://"+subdomain)
        if mode == "A":
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_withoutdomain"]:
                hosts_list.append("https://"+subdomain)
    nuclei_results = nuclei_scan(hosts_list, domain, vulnconf)
    logger.info("Nuclei scan finished")
    if nuclei_results:
        logger.info("Parsing nuclei results...")
        #in ip_dict add vulns key and add the nuclei results
        for ip in ip_dict:
            ip_dict[ip]["vulns"] = []
            for result in nuclei_results:
                if result["host"] == ip:
                    ip_dict[ip]["vulns"].append(result)
        #add vulns key to subdomains and add the nuclei results, split the 'https://' from the subdomain
        for ip in ip_dict:
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_withdomain"]:
                subs_w= ip_dict[ip]["subdomains"]["subdomain_withdomain"]
                ip_dict[ip]["subdomains"]["subdomain_withdomain"][subs_w.index(subdomain)]={}
                ip_dict[ip]["subdomains"]["subdomain_withdomain"][subs_w.index(subdomain)]["vulns"] = []
                for result in nuclei_results:
                    if result["host"] == "https://"+subdomain:
                        ip_dict[ip]["subdomains"]["subdomain_withdomain"][subs_w.index(subdomain)]["vulns"].append(result)
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_with_redirect"]:
                subs_wr= ip_dict[ip]["subdomains"]["subdomain_with_redirect"]
                ip_dict[ip]["subdomains"]["subdomain_with_redirect"][subs_wr.index(subdomain)]={}
                ip_dict[ip]["subdomains"]["subdomain_with_redirect"][subs_wr.index(subdomain)]["vulns"] = []
                for result in nuclei_results:
                    if result["host"] == "https://"+subdomain:
                        ip_dict[ip]["subdomains"]["subdomain_with_redirect"][subs_wr.index(subdomain)]["vulns"].append(result)
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_withoutdomain"]:
                subs_wod= ip_dict[ip]["subdomains"]["subdomain_withoutdomain"]
                ip_dict[ip]["subdomains"]["subdomain_withoutdomain"][subs_wod.index(subdomain)]={}
                ip_dict[ip]["subdomains"]["subdomain_withoutdomain"][subs_wod.index(subdomain)]["vulns"] = []
                for result in nuclei_results:
                    if result["host"] == "https://"+subdomain:
                        ip_dict[ip]["subdomains"]["subdomain_withoutdomain"][subs_wod.index(subdomain)]["vulns"].append(result)
        logger.info("Nuclei results parsed")
    return ip_dict


    
