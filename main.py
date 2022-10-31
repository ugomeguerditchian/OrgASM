from libs import dns_request
from libs import sub_harvester as sh
from libs import result_parser as rp
from libs import ip_scan as ips
from libs import custom_logger as cl
import datetime
import os
import re
from pprint import pprint



def menu():
    #ask for domain name
    domain = input("Enter domain name: ")
    # Check if the domain name is valid with regex
    while not re.match(r"^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,5}$", domain):
        cl.logger.error("Invalid domain name")
        domain = input("Enter domain name: ")
    all_results = []
    #get all the subdomains from alienvault
    cl.logger.info("Alienvault testing...")
    all_results += sh.alienvault_parser(domain)
    cl.logger.info("Alienvault testing done")
    #get all the subdomains from hackertarget
    cl.logger.info("Hackertarget testing...")
    all_results += sh.hacker_target_parser(domain)
    cl.logger.info("Hackertarget testing done")
    #get all the subdomains from wordlist
    all_results += sh.from_wordlist(domain)
    cl.logger.info("Wordlist testing done")
    #delete all the occurences in the list
    cl.logger.info("Deleting occurences...")
    all_results = rp.delete_occurences(all_results)
    dns_result=[]
    for result in all_results:
        print("DNS testing : " + str(round(all_results.index(result) / len(all_results) * 100, 2)) + "%", end="\r")
        #dns_request.main return a list
        #join all the list in one list
        dns_result += dns_request.main(result)
    all_results+= dns_result
    cl.logger.info("DNS testing done")
    cl.logger.info("Deleting occurences...")
    all_results = rp.delete_occurences(all_results)
    cl.logger.info("All done")
    #clear the screen
    try :
        os.system("cls")
    except:
        #linux
        os.system("clear")
    final_dict= rp.result_filter(all_results, domain)
    cl.logger.info(f"Subdomains containing {domain}:\n")
    for subdomain in final_dict["subdomain_withdomain"]:
        cl.logger.info(subdomain)
    cl.logger.info(f"Subdomains not containing {domain}:\n")
    for subdomain in final_dict["subdomain_withoutdomain"]:
        cl.logger.info(subdomain)
    
    cl.logger.info("IP sorting...")
    ip_dict = ips.get_all_ip(all_results, domain)
    cl.logger.info("IP sorting done")
    cl.logger.info("IP sorting results:")
    pprint(ip_dict)
    cl.logger.info("Done")

    cl.logger.info("IP scanning...")
    ip_scan= {}
    for ip, domains in ip_dict.items():
        ip_scan[ip]={}
        ports_for_ip= ips.detect_open_ports(ip)
        for port in ports_for_ip:
            ip_scan[ip][port]["service"]= ips.detect_service(ip, port)
            print("IP scanning : " + str(round(ip_dict.index(ip) / len(ip_dict) * 100, 2)) + "%", end="\r")
    
    cl.logger.info("IP scanning done")
    cl.logger.info("IP scanning results:")
    for ip in ip_scan:
        cl.logger.info(f"{ip} : {ip_scan[ip]}")
    cl.logger.info("Done")
    
    
    #ask if the user want to save the results
    save = input("\nDo you want to save the results? (y/n): ")
    if save == "y":
        cl.logger.info("Saving results...")
        #save the results
        date = datetime.today().strftime("%Y%m%d%h%m")
        domain_safe = domain.replace(".", "_")
        with open(f"results_{domain_safe}_{date}.txt", "w") as f:
            f.write(f"Subdomains containing {domain}:\n")
            for subdomain in final_dict["subdomain_withdomain"]:
                f.write(subdomain + "\n")
            f.write(f"\nSubdomains not containing {domain}:\n")
            for subdomain in final_dict["subdomain_withoutdomain"]:
                f.write(subdomain + "\n")
            f.close()
        cl.logger.info(f"Results saved in results_{domain}_{date}.txt")



menu()

