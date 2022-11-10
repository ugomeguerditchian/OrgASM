import csv
def delete_occurences(list : list):
    #delete all the occurences in a list
    #example: [1,2,3,4,5,1,2,3,4,5] -> [1,2,3,4,5]
    new_list = []
    for i in list:
        if i not in new_list:
            new_list.append(i)
    return new_list

def result_filter(list : list, domain : str, subdomain_with_redirect:list) -> dict :
    #from the list of sudbomains return all subomains containing the domain
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
        "subdomain_with_redirect": []
    }
    for subdomain in list:
        if domain in subdomain:
            dict["subdomain_withdomain"].append(subdomain)
        else:
            dict["subdomain_withoutdomain"].append(subdomain)
    dict["subdomain_with_redirect"] = subdomain_with_redirect
    return dict

def service_recognizer(scan_dict :dict) -> dict:
    #open the file with all the services in wordlists/tcp.csv
    #the csv file is in the format:
    """
    Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Unauthorized Use Reported,Assignment Notes

    """
    #get only service name and port number for tcp
    tcp_services = {}
    with open("wordlists/service-names-port-numbers.csv", "r") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[2] == "tcp":
                tcp_services[row[1]] = row[0]

    #scan_dict is in the format:
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
    #if in scan_dict there is a service in state "None" it will be replaced with the service in the csv file
    for ip in scan_dict:
        try: 
            for port in scan_dict[ip]["ports"]:
                if scan_dict[ip]["ports"][port] == None or scan_dict[ip]["ports"][port] == "null":
                    if str(port) in tcp_services:
                        scan_dict[ip]["ports"][port] = tcp_services[str(port)]
                    else:
                        scan_dict[ip]["ports"][port] = "Unknown"
        except:
            pass
    return scan_dict
