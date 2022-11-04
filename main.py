from libs import dns_request
from libs import sub_harvester as sh
from libs import result_parser as rp
from libs import ip_scan as ips
from libs import custom_logger as cl
from libs import domain_parser as dp
import datetime
import os
import json
import re
from pprint import pprint
import argparse
logger = cl.logger



def menu():
    argpars = argparse.ArgumentParser()
    argpars.add_argument("-d", "--domain", required=False, help="Domain to scan")
    argpars.add_argument("-w", "--wordlist", default="medium", type=str, required=False, help="Wordlist to use (small, medium(default), big)")
    argpars.add_argument("-wT", "--wordlistThreads", default=500, type=int, required=False, help="Number of threads to use for Wordlist(default 500)")
    argpars.add_argument("-iT", "--IPthreads", default=2000, type=int, required=False, help="Number of threads to use for DNS requests(default 2000)")
    argpars.add_argument("-sT", "--SubdomainsThreads", default=500, type=int, required=False, help="Number of threads to use for check real subdomains(default 500)")
    argpars.add_argument("-o", "--output", default=False, action="store_true", help="If provided > save the results, default is False")

    args = argpars.parse_args()

    # help for argpars
    domain = ""
    if args.domain:
        domain = args.domain
    else:
        domain = input("Enter domain to scan: ")
    

    output = args.output

    final_dict_result = {}
    #ask for domain name
    # Check if the domain name is valid with regex
    while not re.match(r"^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,5}$", domain):
        logger.error("Invalid domain name")
        domain = input("Enter domain name: ")
    all_results = []
    #get all the subdomains from alienvault
    logger.info("Alienvault testing...")
    all_results += sh.alienvault_parser(domain)
    logger.info("Alienvault testing done")
    #get all the subdomains from hackertarget
    logger.info("Hackertarget testing...")
    all_results += sh.hacker_target_parser(domain)
    logger.info("Hackertarget testing done")
    #get all the subdomains from crt.sh
    logger.info("Crt.sh testing...")
    all_results += sh.crtsh_parser(domain)
    logger.info("Crt.sh testing done")
    #get all the subdomains from wordlist
    #ask for small, medium or large wordlist
    if args.wordlist:
        wordlist_size = args.wordlist
    else:
        wordlist_size = input("Wordlist size (small, medium, big): ")
        while wordlist_size not in ["small", "medium", "big"]:
            logger.error("Invalid wordlist size")
            wordlist_size = input("Wordlist size (small, medium, big): ")
    
    #ask for how many threads to use for the wordlist
    if args.wordlistThreads:
        wordlist_thread_number = int(args.wordlistThreads)
    else:
        wordlist_thread_number = int(input("Enter number of threads to use for the wordlist scan: "))
    
    logger.info("Wordlist testing...")
    all_results += sh.from_wordlist_thread(domain, wordlist_thread_number, f"wordlists/{wordlist_size}.txt")
    logger.info("Wordlist testing done")
    #delete all the occurences in the list
    logger.info("Deleting occurences...")
    all_results = rp.delete_occurences(all_results)


    dns_result=[]
    #check subdomains by accessing them with dp.detect_redirect
    cl.logger.info("Checking subdomains...")
    all_results += dp.detect_redirect_with_thread_limit(all_results, args.SubdomainsThreads)
    cl.logger.info("Checking subdomains done")
    for result in all_results:
        print("DNS testing : " + str(round(all_results.index(result) / len(all_results) * 100, 2)) + "% ", end="\r")
        #dns_request.main return a list
        #join all the list in one list
        dns_result += dns_request.main(result)
    all_results+= dns_result
    logger.info("DNS testing done")
    logger.info("Deleting occurences...")
    all_results = rp.delete_occurences(all_results)
    logger.info("All done")
    #clear the screen
    try :
        os.system("cls")
    except:
        # linux
        os.system("clear")

    
    final_dict= rp.result_filter(all_results, domain)
    logger.info(f"Subdomains containing {domain}:")
    for subdomain in final_dict["subdomain_withdomain"]:
        print(subdomain)
    logger.info(f"Subdomains not containing {domain}:")
    for subdomain in final_dict["subdomain_withoutdomain"]:
        print(subdomain)
    
    logger.info("IP sorting...")
    ip_dict = ips.get_all_ip(all_results, domain)
    logger.info("IP sorting done")
    logger.info("IP sorting results:")
    pprint(ip_dict)
    logger.info("Done")
    final_dict_result= ip_dict
    logger.info("IP scanning...")
    if args.IPthreads:
        ip_thread_number = int(args.IPthreads)
    else:
        ip_thread_number = int(input("Enter number of threads to use for the IP scan: "))
    for ip, domains in final_dict_result.items():
        ports_for_ip= ips.port_scan_with_thread_limit(ip, range(65536), ip_thread_number)
        #print loading
        # print("IP scanning : " + str(round(list(final_dict_result.keys()).index(ip) / len(final_dict_result.keys()) * 100, 2)) + "%", end="\r")
        final_dict_result[ip]["ports"]={}
        for port in ports_for_ip:
            final_dict_result[ip]["ports"][port]={}
            final_dict_result[ip]["ports"][port]["service"]= ips.detect_service(ip, port)
    
    logger.info("IP scanning done")
    logger.info("IP scanning service analysis...")
    final_dict_result= rp.service_recognizer(final_dict_result)
    logger.info("IP scanning results:")
    pprint(final_dict_result)
    logger.info("Done")
    save = ""
    if not output:
        while save.lower() != "y" and save.lower() != "n":
            save = input("Do you want to save the result? (y/n): ")
    else:
        if output:
            save = "y"
        else :
            save = "n"
    if not os.path.exists("exports"):
        os.mkdir("exports")
    if save.lower() == "y":
        date = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        file_name = f"result_{domain.replace('.','-')}_{date}.json"
        with open("exports/"+file_name, "w") as f:
            json.dump(final_dict_result, f, indent=4)
        logger.info(f"File saved in exports/{file_name}")
    logger.info("Exiting...")

if __name__ == "__main__":
    menu()

