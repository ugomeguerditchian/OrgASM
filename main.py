from libs import dns_request
from libs import sub_harvester as sh
from libs import result_parser as rp
import os



def menu():
    #ask for domain name
    domain = input("Enter domain name: ")
    all_results = []
    #get all the subdomains from alienvault
    print("Alienvault testing...")
    all_results += sh.alienvault_parser(domain)
    print("Alienvault testing done")
    #get all the subdomains from hackertarget
    print("Hackertarget testing...")
    all_results += sh.hacker_target_parser(domain)
    print("Hackertarget testing done")
    #get all the subdomains from wordlist
    all_results += sh.from_wordlist(domain)
    print("Wordlist testing done")
    #delete all the occurences in the list
    print("Deleting occurences...")
    all_results = rp.delete_occurences(all_results)
    dns_result=[]
    print("DNS testing...")
    for result in all_results:
        #dns_request.main return a list
        #join all the list in one list
        dns_result += dns_request.main(result)
    all_results+= dns_result
    print("DNS testing done")
    print("Deleting occurences...")
    all_results = rp.delete_occurences(all_results)
    print("All done")
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



menu()

