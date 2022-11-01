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
import argparse 



def menu():
    argpars = argparse.ArgumentParser()
    argpars.add_argument("-d", "--domain", required=False, help="Domain to scan")
    argpars.add_argument("-t", "--threads", required=False, help="Number of threads to use (recommended 300)")
    argpars.add_argument("-o", "--output", choices=["True", "False"],required=False, default=False, help="Output save, default is False")

    args = argpars.parse_args()
    # help for argpars
    domain = ""
    if args.domain:
        domain = args.domain
    else:
        domain = input("Enter domain to scan: ")
    
    thread_number = 10
    if args.threads:
        thread_number = int(args.threads)
    else:
        thread_number = int(input("Enter number of threads to use: "))
    
    output = False
    if args.output:
        output = bool(args.output)

    final_dict_result = {}
    #ask for domain name
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
    cl.logger.info(f"Subdomains containing {domain}:")
    for subdomain in final_dict["subdomain_withdomain"]:
        print(subdomain)
    cl.logger.info(f"Subdomains not containing {domain}:")
    for subdomain in final_dict["subdomain_withoutdomain"]:
        print(subdomain)
    
    cl.logger.info("IP sorting...")
    ip_dict = ips.get_all_ip(all_results, domain)
    cl.logger.info("IP sorting done")
    cl.logger.info("IP sorting results:")
    pprint(ip_dict)
    cl.logger.info("Done")
    final_dict_result= ip_dict
    cl.logger.info("IP scanning...")
    #ask for how many thread to use
    for ip, domains in final_dict_result.items():
        ports_for_ip= ips.detect_open_port_thread(ip, thread_number)
        for port in ports_for_ip:
            final_dict_result[ip]["ports"]={}
            final_dict_result[ip]["ports"][port]={}
            print(f"Port scan service for {ip} : " + str(round(ports_for_ip.index(port) / len(ports_for_ip) * 100, 2)) + "%" + " "*8, end="\r")
            final_dict_result[ip]["ports"][port]["service"]= ips.detect_service(ip, port)
    
    cl.logger.info("IP scanning done")
    cl.logger.info("IP scanning service analysis...")
    final_dict_result= rp.service_recognizer(final_dict_result)
    cl.logger.info("IP scanning results:")
    pprint(final_dict_result)
    cl.logger.info("Done")
    save = ""
    if not output:
        save = input("Do you want to save the result? (y/n): ")
    else:
        if output:
            save = "y"
        else :
            save = "n"
    if not os.path.exists("exports"):
        os.mkdir("exports")
    if save == "y":
        # Get the current date and format it as YY-mm-dd-hh-mm-ss
        date = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        file_name = f"result_{domain.replace('.','-')}_{date}.json"
        with open("exports/"+file_name, "w") as f:
            json.dump(final_dict_result, f, indent=4)
        cl.logger.info(f"File saved in exports/{file_name}")
    cl.logger.info("Exiting...")

menu()

