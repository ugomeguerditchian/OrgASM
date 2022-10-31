from libs import dns_request
from libs import sub_harvester as sh
from libs import result_parser as rp
from libs import ip_scan as ips
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
    for result in all_results:
        print("DNS testing : " + str(round(all_results.index(result) / len(all_results) * 100, 2)) + "%", end="\r")
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
    
    print("\nIP sorting...")
    ip_dict = ips.get_all_ip(all_results, domain)
    print("IP sorting done")
    print("\nIP sorting results:\n")
    for ip in ip_dict:
        print(f"{ip} : {ip_dict[ip]}")
    print("\nDone")

    print("IP scanning...")
    ip_scan= {}
    for ip, domains in ip_dict.items():
        ip_scan[ip]={}
        ports_for_ip= ips.detect_open_ports(ip)
        for port in ports_for_ip:
            ip_scan[ip][port]["service"]= ips.detect_service(ip, port)
    
    print("IP scanning done")
    print("\nIP scanning results:\n")
    for ip in ip_scan:
        print(f"{ip} : {ip_scan[ip]}")
    print("\nDone")
    



    #ask if the user want to save the results
    save = input("\nDo you want to save the results? (y/n): ")
    if save == "y":
        #save the results
        with open("results.txt", "w") as f:
            f.write(f"Subdomains containing {domain}:\n")
            for subdomain in final_dict["subdomain_withdomain"]:
                f.write(subdomain + "\n")
            f.write(f"\nSubdomains not containing {domain}:\n")
            for subdomain in final_dict["subdomain_withoutdomain"]:
                f.write(subdomain + "\n")
            f.close()
        print("Results saved in results.txt")



menu()

