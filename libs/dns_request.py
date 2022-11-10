#from domain name get dns information and detect all subdomain associated
import dns.resolver
import requests
import socket
import json
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool


def get_dns_information(domain):
    #get the dns information of the domain with dnspyton
    #return a list of dns information
    dns_informations= []
    #set timeout to 0.2 seconds
    socket.setdefaulttimeout(0.2)
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
    try :
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
    try :
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
    try :
        answers = dns.resolver.resolve(domain, 'AAAA')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
    try :
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
    try :
        #get the dns information
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
    return dns_informations

def get_dns_informations_thread(domain :str, threads_number:int) :
    dns_informations=[]

    with ThreadPoolExecutor(max_workers=threads_number) as executor:
        results = executor.map(get_dns_information, domain)
        for result in results:
            dns_informations+= result
    return dns_informations

def detect_subdomain(dns_information :list) -> list:
    #detect all the subdomain from the dns information
    #return a list of subdomain
    subdomains = []
    for dns in dns_information:
        #get the dns information
        dns = str(dns)
        #split the dns information
        dns = dns.split(" ")
        #get the subdomain
        subdomain = dns[0]
        #add the subdomain to the list
        subdomains.append(subdomain)
    return subdomains

def detect_real_subdomain(subdomains :list) -> list:
    #detect all the real subdomain from the list of subdomain
    #return a list of real subdomain
    real_subdomains = []
    for subdomain in subdomains:
        #test if the subdomain is real
        try:
            #try to connect to the subdomain
            socket.gethostbyname(subdomain)
            #if the connection is successful, add the subdomain to the list
            real_subdomains.append(subdomain)
        except:
            pass
    return real_subdomains

def delete_ip_from_list(subdomains :list) -> list:
    #delete all the ip address from the list of subdomain
    #return a list of subdomain
    subdomains_without_ip = []
    for subdomain in subdomains:
        #test if the subdomain is an ip address
        try:
            #try to convert the subdomain to an ip address
            socket.inet_aton(subdomain)
        except:
            #if the subdomain is not an ip address, add it to the list
            subdomains_without_ip.append(subdomain)
    return subdomains_without_ip

def test_dns_zone_transfer(domain :str) -> list:
    #test if the dns zone transfer is enable
    #return a list of subdomain
    subdomains = []
    #get the dns server
    dns_server = dns.resolver.resolve(domain, 'NS')
    #test if the dns zone transfer is enable
    for server in dns_server:
        #get the dns server
        server = str(server)
        #split the dns server
        server = server.split(" ")
        #get the dns server
        server = server[0]
        #test if the dns zone transfer is enable
        try:
            #try to get the dns zone transfer
            answers = dns.query.xfr(server, domain)
            #if the dns zone transfer is enable, add the subdomain to the list
            for answer in answers:
                subdomains.append(answer)
        except:
            pass
    return subdomains

def main(domain, threads_number):
    #get the dns information
    dns_information = get_dns_informations_thread(domain, threads_number)
    #detect all the subdomain
    subdomains = detect_subdomain(dns_information)
    #detect all the real subdomain
    real_subdomains = detect_real_subdomain(subdomains)
    #delete all the ip address from the list of subdomain
    subdomains_without_ip = delete_ip_from_list(real_subdomains)
    #return the list of subdomain
    return subdomains_without_ip
