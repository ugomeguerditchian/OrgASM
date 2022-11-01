from libs import dns_request
from libs import sub_harvester as sh
from libs import result_parser as rp
from libs import ip_scan as ips
from libs import custom_logger as cl
import datetime
import os
import json
import re
from pprint import pprint



def menu():
    final_dict_result = {}
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
    print(f"Subdomains containing {domain}:\n")
    for subdomain in final_dict["subdomain_withdomain"]:
        print(subdomain)
    print(f"\nSubdomains not containing {domain}:\n")
    for subdomain in final_dict["subdomain_withoutdomain"]:
        print(subdomain)
    
    cl.logger.info("IP sorting...")
    ip_dict = ips.get_all_ip(all_results, domain)
    cl.logger.info("IP sorting done")
    cl.logger.info("IP sorting results:")
    for ip in ip_dict:
        print(f"{ip} : {ip_dict[ip]}")
    cl.logger.info("Done")
    final_dict_result= ip_dict
    cl.logger.info("IP scanning...")
    #ask for how many thread to use
    thread_number = int(input("Enter the number of thread to use: "))
    for ip, domains in final_dict_result.items():
        ports_for_ip= ips.detect_open_port_thread(ip, thread_number)
        for port in ports_for_ip:
            final_dict_result[ip]["ports"]={}
            final_dict_result[ip]["ports"][port]={}
            print(f"Port scan service for {ip} : " + str(round(ports_for_ip.index(port) / len(ports_for_ip) * 100, 2)) + "%", end="\r")
            final_dict_result[ip]["ports"][port]["service"]= ips.detect_service(ip, port)
            #ip_scan[ip][port]["banner"]= ips.detect_banner(ip, port)
    
    print("IP scanning done")
    cl.logger.info("IP scanning service analysis...")
    final_dict_result= rp.service_recognizer(final_dict_result)
    print("\nIP scanning results:\n")
    for ip in final_dict_result:
        print(f"{ip} : {final_dict_result[ip]}")
    print("\nDone")
    



    #ask if the user want to save the result
    save = input("Do you want to save the result? (y/n): ")
    #ask for the name of the file
    #detect if folderse exports exist
    if not os.path.exists("exports"):
        os.mkdir("exports")
    if save == "y":
        file_name = input("Enter the name of the file: ")
        with open("exports/"+file_name, "w") as f:
            json.dump(final_dict_result, f, indent=4)
        print("File saved")
        exit()
    else:
        print("Exiting...")
        exit()



menu()

