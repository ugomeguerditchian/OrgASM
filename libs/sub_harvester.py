import requests
from libs import result_parser as rp
import json
import socket
import threading
from libs import custom_logger
logger = custom_logger.logger


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
    subdomains = rp.delete_occurences(subdomains)
    return subdomains

def crtsh_parser(domain):
    #get all the subdomain of the domain from crtsh
    url= f"https://crt.sh/?q={domain}&output=json"
    #user agent firefox
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"
    }
    try :
        response = requests.get(url, headers=headers)
        #response is a json format
        #convert response.text in json
        json_data = json.loads(response.text)
        """
        Example of json_data from crtsh :
        [
        {
            "issuer_ca_id": 183267,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "www.anne.fage.fr",
            "name_value": "anne.fage.fr\nwww.anne.fage.fr",
            "id": 7882196717,
            "entry_timestamp": "2022-11-01T21:06:38.933",
            "not_before": "2022-11-01T20:06:38",
            "not_after": "2023-01-30T20:06:37",
            "serial_number": "030da3a68189369d6475a61ad5ec6618a11c"
        },
        {
            "issuer_ca_id": 183267,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "www.anne.fage.fr",
            "name_value": "anne.fage.fr\nwww.anne.fage.fr",
            "id": 7882190984,
            "entry_timestamp": "2022-11-01T21:06:38.353",
            "not_before": "2022-11-01T20:06:38",
            "not_after": "2023-01-30T20:06:37",
            "serial_number": "030da3a68189369d6475a61ad5ec6618a11c"
        }]
        """
        #get all the common_name and name_value
        subdomains = []
        for item in json_data:
            subdomains.append(item["common_name"])
            #split name_value in lines
            lines = item["name_value"].split("\n")
            for line in lines:
                subdomains.append(line)
        return subdomains
    except Exception as e:
        logger.error("Impossible to get subdomains from crtsh")
        return []
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
    subdomains = rp.delete_occurences(subdomains)
    return subdomains



def from_wordlist(domain, wordlist_chunks):
    #wordlist is Subdomain.txt
    #open the file

    #test all the subdomains like {subdomain}.{domain}
    subdomains = []
    for line in wordlist_chunks:
        #delete the \n
        line = line.replace("\r", "")
        #loaading percentage
        print(f"Wordlist testing : {str(round(wordlist_chunks.index(line) / len(wordlist_chunks) * 100, 2))}% ", end="\r")
        request_to_test = line.strip() + "." + domain
        try:
            #try to connect to the subdomain
            #detect if there is a redirection
            #if there is a redirection, check if the redirection is the same as the actual subdomain tested
            #if the redirection is the same as the actual subdomain tested, add the subdomain to the list
            #if the redirection is not the same as the actual subdomain tested, don't add the subdomain to the list
            #if there is no redirection, add the subdomain to the list
            socket.gethostbyname(request_to_test)
            #if the connection is successful, add the subdomain to the list
            subdomains.append(request_to_test)
        except:
            pass
    return subdomains
def divide_chunks(l, n):
     
    # looping till length l
    for i in range(0, len(l), n):
        yield l[i:i + n]

def from_wordlist_thread(domain, thread_number, wordlist):
    with open(wordlist, "r") as file:
        #read all the lines
        lines = file.readlines()
    #delete all \n
    lines = [line.replace("\n", "") for line in lines]
    ranges= list(divide_chunks(lines, len(lines) // thread_number))
    subdomains = []
    threads = []
    for i in ranges:
        t = threading.Thread(target= lambda: subdomains.append(from_wordlist(domain, i)))
        threads.append(t)
        t.start()
    for i in threads:
        i.join()
    final_subdomains = []
    for i in subdomains:
        final_subdomains += i
    final_subdomains = rp.delete_occurences(final_subdomains)
    return final_subdomains