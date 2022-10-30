#from domain name get dns information and detect all subdomain associated
import dns.resolver
import requests
import socket
import json

def get_dns_information(domain):
    #get the dns information of the domain with dnspyton
    #return a list of dns information
    dns_informations= []
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
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            dns_informations.append(rdata)
    except:
        pass
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

def main(domain):
    #get the dns information
    dns_information = get_dns_information(domain)
    #detect all the subdomain
    subdomains = detect_subdomain(dns_information)
    #detect all the real subdomain
    real_subdomains = detect_real_subdomain(subdomains)
    #delete all the ip address from the list of subdomain
    subdomains_without_ip = delete_ip_from_list(real_subdomains)
    #return the list of subdomain
    return subdomains_without_ip
