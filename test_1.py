from libs import dns_request
import requests
import json
import requests
import socket

def delete_occurences(list : list):
    #delete all the occurences in a list
    #example: [1,2,3,4,5,1,2,3,4,5] -> [1,2,3,4,5]
    new_list = []
    for i in list:
        if i not in new_list:
            new_list.append(i)
    return new_list

def alienvault_parser(domain):
    #get all the subdomain of the domain from alienvault
    #url https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
    url = "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns"
    response = requests.get(url)
    #response is a json format
    #convert response.text in json
    json_data = json.loads(response.text)
    """
    Example of json_data from alienvault
        {
        "passive_dns": [
            {
                "address": "144.76.196.152",
                "first": "2022-10-22T14:19:06",
                "last": "2022-10-22T14:19:06",
                "hostname": "res01.benoit.fage.fr",
                "record_type": "A",
                "indicator_link": "/indicator/hostname/res01.benoit.fage.fr",
                "flag_url": "assets/images/flags/de.png",
                "flag_title": "Germany",
                "asset_type": "hostname",
                "asn": "AS24940 hetzner online gmbh"
            },
            {
                "address": "82.66.13.124",
                "first": "2022-09-24T01:09:12",
                "last": "2022-09-24T01:15:02",
                "hostname": "dolibarr.benoit.fage.fr",
                "record_type": "A",
                "indicator_link": "/indicator/hostname/dolibarr.benoit.fage.fr",
                "flag_url": "assets/images/flags/fr.png",
                "flag_title": "France",
                "asset_type": "hostname",
                "asn": "AS12322 free sas"
            }
    """
    #get all the hostname
    subdomains = []
    for i in json_data["passive_dns"]:
        try :
            subdomains.append(i["hostname"])
        except:
            pass
    #delete all the occurences in the list
    subdomains = delete_occurences(subdomains)
    return subdomains

def hacker_target_parser(domain):
    #get all the subdomain of the domain from hackertarget
    #the url is https://api.hackertarget.com/hostsearch/?q={domain}
    url = "https://api.hackertarget.com/hostsearch/?q=" + domain
    response = requests.get(url)
    """
    the response is in this form :
    fage.fr,81.88.53.29
    jean-marie.fage.fr,185.2.5.85
    anne.fage.fr,185.2.5.85
    benoit.fage.fr,157.90.145.185
    pizza.benoit.fage.fr,157.90.145.185
    content.pizza.benoit.fage.fr,172.104.159.223
    admin.benoit.fage.fr,157.90.145.185
    dolibarr.benoit.fage.fr,82.66.13.124
    content.benoit.fage.fr,157.90.145.185
    """
    #split the response in lines
    lines = response.text.split("\n")
    #get all the subdomains
    subdomains = []
    for line in lines:
        subdomains.append(line.split(",")[0])
    #delete all the occurences in the list
    subdomains = delete_occurences(subdomains)
    return subdomains

def from_wordlist(domain):
    #wordlist is Subdomain.txt
    #open the file
    with open("wordlists/subdomains-1000.txt", "r") as file:
        #read all the lines
        lines = file.readlines()
    #test all the subdomains like {subdomain}.{domain}
    subdomains = []
    for line in lines:
        request_to_test = line.strip() + "." + domain
        try:
            #try to connect to the subdomain
            socket.gethostbyname(request_to_test)
            #if the connection is successful, add the subdomain to the list
            subdomains.append(request_to_test)
        except:
            pass
        subdomains = delete_occurences(subdomains)
    return subdomains


def menu():
    #ask for domain name
    domain = input("Enter domain name: ")
    all_results = []
    #get all the subdomains from alienvault
    all_results += alienvault_parser(domain)
    #get all the subdomains from hackertarget
    all_results += hacker_target_parser(domain)
    #get all the subdomains from wordlist
    all_results += from_wordlist(domain)
    #delete all the occurences in the list
    all_results = delete_occurences(all_results)
    dns_result=[]
    for result in all_results:
        dns_result.append(dns_request.main(result))
    all_results = all_results + dns_result
    all_results = delete_occurences(all_results)
    print(all_results)



menu()

