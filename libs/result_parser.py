import csv
import os
from libs import custom_logger as cl

logger = cl.logger
import socket


def delete_occurences(list: list):
    # delete all the occurences in a list
    # example: [1,2,3,4,5,1,2,3,4,5] -> [1,2,3,4,5]
    new_list = []
    for i in list:
        if i not in new_list:
            new_list.append(i)
    return new_list


def delete_star(list: list) -> list:
    # delete all the occurences of * in a list
    new_list = []
    for i in list:
        if i != "*":
            new_list.append(i)
    return new_list


def result_filter(
    list: list,
    domain: str,
    subdomain_with_redirect: list,
    dead_subdomains: list,
    dns_exist: list,
) -> dict:
    # from the list of sudbomains return all subomains containing the domain
    """
    dict = {
        "subdomain_withdomain": [],
        "subdomain_withoutdomain": [],
        "subdomain_with_redirect": []
    }
    """
    dict = {
        "subdomain_withdomain": [],
        "subdomain_withoutdomain": [],
        "subdomain_with_redirect": [],
        "dead_subdomains": [],
        "dns_exist": [],
    }
    for subdomain in list:
        if domain in subdomain:
            dict["subdomain_withdomain"].append(subdomain)
        else:
            dict["subdomain_withoutdomain"].append(subdomain)
    dict["subdomain_with_redirect"] = subdomain_with_redirect
    dict["dead_subdomains"] = dead_subdomains
    dict["dns_exist"] = dns_exist
    return dict


def dynamic_save(all_results: dict, domain: str, mode: str):
    up = []
    down = []
    if mode == "create":
        if all_results:
            if not os.path.exists(f"exports/{domain}"):
                os.makedirs(f"exports/{domain}")
            with open(f"exports/{domain}/dynamic_sub_save.txt", "w") as file:
                for sub in all_results:
                    # do dns resolution
                    try:
                        # timeout is 1 second
                        socket.setdefaulttimeout(0.5)
                        ip = socket.gethostbyname(sub)
                        up.append(sub)
                    except:
                        down.append(sub)
                # first write the up subdomains
                file.write("Up subdomains: \r \r")
                for sub in up:
                    file.write(sub + "\r")
                file.write("\r \r")
                # then write the down subdomains
                file.write("Down subdomains: \r \r")
                for sub in down:
                    file.write(sub + "\r")
                file.write("\r \r")
        else:
            logger.error("No subdomains found, exiting...")
            exit(1)
    if mode == "add":
        # add the new subdomains to the file
        if all_results:
            for sub in all_results:
                # do dns resolution
                try:
                    # timeout is 1 second
                    socket.setdefaulttimeout(0.5)
                    ip = socket.gethostbyname(sub)
                    up.append(sub)
                except:
                    down.append(sub)
            # first write the up subdomains to the right position in the file
            with open(f"exports/{domain}/dynamic_sub_save.txt", "r") as file:
                lines = file.readlines()
                for i in range(len(lines)):
                    if lines[i] == "Up subdomains: \r \r":
                        position = i
            with open(f"exports/{domain}/dynamic_sub_save.txt", "a") as file:
                for sub in up:
                    file.write(sub + "\r")
            # then write the down subdomains to the right position in the file
            with open(f"exports/{domain}/dynamic_sub_save.txt", "r") as file:
                lines = file.readlines()
                for i in range(len(lines)):
                    if lines[i] == "Down subdomains: \r \r":
                        position = i
            with open(f"exports/{domain}/dynamic_sub_save.txt", "a") as file:
                for sub in down:
                    file.write(str(sub), "\r")
        else:
            logger.error("No subdomains found, exiting...")
            exit(1)


def service_recognizer(scan_dict: dict) -> dict:
    # open the file with all the services in wordlists/tcp.csv
    # the csv file is in the format:
    """
    Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Unauthorized Use Reported,Assignment Notes

    """
    # get only service name and port number for tcp
    tcp_services = {}
    with open("wordlists/service-names-port-numbers.csv", "r") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[2] == "tcp":
                tcp_services[row[1]] = row[0]

    # scan_dict is in the format:
    """
    1.1.1.1{
        "ports":{
            "80":{
                "service": "http"
                }
        }
        "subdomains":[]
    }
    """
    # if in scan_dict there is a service in state "None" it will be replaced with the service in the csv file
    for ip in scan_dict:
        try:
            for port in scan_dict[ip]["ports"]:
                if (
                    scan_dict[ip]["ports"][port] == None
                    or scan_dict[ip]["ports"][port] == "null"
                ):
                    if str(port) in tcp_services:
                        scan_dict[ip]["ports"][port] = tcp_services[str(port)]
                    else:
                        scan_dict[ip]["ports"][port] = "Unknown"
        except:
            pass
    return scan_dict
