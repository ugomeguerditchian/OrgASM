import requests
import dns
from pythonping import ping
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
import webtech
def detect_redirect(url: str) -> bool:
    if check_up(url) :
        try:
            
                response = requests.get("https://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
        except:
            try :
                if check_up(url) :
                    response = requests.get("http://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
            except:
                return False
        try :
            if response.history:
                #split response.url to get the domain
                url_redirected= response.url.split("//")[1]
                domain = url_redirected.split("/")[0]
                if url_redirected == url:
                    return False
                return domain
            else:
                return False
        except:
            return False
    else :
        return "dead"

def try_access_web_port(url: str) -> bool:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    try:
        response = requests.get("http://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=3, verify=False)
        if response.status_code == 400 :
            raise Exception("Bad request")
    except:
        try :
            response = requests.get("https://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=3, verify=False)
        except:
            return False
    if response.status_code == 200:
        #return the x-powered-by header
        return True
    else:
        return False

def detect_redirect_with_thread_limit(subdomains: list, thread_number: int) -> list:
    real_subdomains = []
    subdomains_with_redirect = []
    dead_subdomains = []
    with ThreadPoolExecutor(thread_number) as executor:
        results = executor.map(detect_redirect, subdomains)
        for subdomain, is_redirect in zip(subdomains, results):
            if is_redirect == True:
                if is_redirect not in subdomains and is_redirect != "" :
                    real_subdomains.append(is_redirect)
                    #print(f'> {subdomain} is a redirect')
                subdomains_with_redirect.append(subdomain)
            elif is_redirect == None:
                pass
            elif is_redirect == "dead":
                dead_subdomains.append(subdomain)
            else:
                #print(f'> {subdomain} is not a redirect')
                real_subdomains.append(subdomain)
    return real_subdomains, subdomains_with_redirect, dead_subdomains

def detect_web_port(ip_dict :dict, thread_number: int, scan_mode: str) -> dict:
    with ThreadPoolExecutor(thread_number) as executor:
        for ip in ip_dict:
            if (scan_mode == "W" and ip_dict[ip]["subdomains"]["subdomain_withdomain"] != []) or (scan_mode == "WR" and ip_dict[ip]["subdomains"]["subdomain_withdomain"] != [] or ip_dict[ip]["subdomains"]["subdomain_with_redirect"] != []) or (scan_mode =="A") :
                for port, service in ip_dict[ip]["ports"].items():
                    print(f"Checking if {ip}:{port} is a web port")
                    result = executor.submit(try_access_web_port, f"{ip}:{port}")
                    if result.result() != False:
                        ip_dict[ip]["ports"][port] = "website"
    return ip_dict

def detect_web_techno(ip_dict: dict, mode: str) -> dict:
    for ip in ip_dict:
        if (mode == "W" and ip_dict[ip]["subdomains"]["subdomain_withdomain"] != []) or (mode == "WR" and ip_dict[ip]["subdomains"]["subdomain_withdomain"] != [] or ip_dict[ip]["subdomains"]["subdomain_with_redirect"] != []) or (mode =="A") :
            for port, service in ip_dict[ip]["ports"].items():
                if service == "website":
                    print(f"Detecting web technology for {ip}:{port}")
                    try:
                        result = webtech.WebTech(options={'json': True}).start_from_url(f"http://{ip}:{port}")
                    except:
                        try:
                            result = webtech.WebTech(options={'json': True}).start_from_url(f"https://{ip}:{port}")
                        except:
                            result = {}
                    if result != {}:
                        ip_dict[ip]["ports"][port] = result
    return ip_dict

def detect_web_techno_domain(ip_dict: dict, mode: str) -> dict:
    for ip in ip_dict:
        ip_dict[ip]["subdomains"]["web_techno"]={}
        if mode == "W" or mode=="WR" or mode== "A":
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_withdomain"]:
                print(f"Detecting web technology for {subdomain}")
                try:
                    result = webtech.WebTech(options={'json': True}).start_from_url(f"http://{subdomain}")
                except:
                    try:
                        result = webtech.WebTech(options={'json': True}).start_from_url(f"https://{subdomain}")
                    except:
                        result = {}
                if result != {}:
                    ip_dict[ip]["subdomains"]["web_techno"][subdomain] = result
        if mode == "WR" or mode== "A":
            for subdomain in ip_dict[ip]["subdomains"]["subdomain_with_redirect"]:
                print(f"Detecting web technology for {subdomain}")
                try:
                    result = webtech.WebTech().start_from_url(f"http://{subdomain}")
                except:
                    try:
                        result = webtech.WebTech().start_from_url(f"https://{subdomain}")
                    except:
                        result = {}
                if result != {}:
                    ip_dict[ip]["subdomains"]["web_techno"][subdomain] = result
    return ip_dict
def check_up(url: str) -> bool:
    try:
        response = requests.get(url, headers={'User-Agent': 'Google Chrome'}, timeout=3)
    except:
        # Use ping to check if the server is up
        try:
            ping(url, timeout=1)
            return True
        except Exception as e:
            #print(e)
            return False
    if response.status_code == 200:
        return True
    else:
        return False

def check_dns(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

if __name__ == "__main__":
    print(check_up("benoit.fage.fr"))
    print(detect_redirect("benoit.fage.fr"))
    # print(check_up("https://content.pizza.benoit.fage.fr"))