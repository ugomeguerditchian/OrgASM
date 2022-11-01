import csv
def delete_occurences(list : list):
    #delete all the occurences in a list
    #example: [1,2,3,4,5,1,2,3,4,5] -> [1,2,3,4,5]
    new_list = []
    for i in list:
        if i not in new_list:
            new_list.append(i)
    return new_list

def result_filter(list : list, domain : str) -> dict :
    #from the list of sudbomains return all subomains containing the domain
    """
    dict = {
        "subdomain_withdomain": [],
        "subdomain_withoutdomain": []
    }
    """
    dict = {
        "subdomain_withdomain": [],
        "subdomain_withoutdomain": []
    }
    for subdomain in list:
        if domain in subdomain:
            dict["subdomain_withdomain"].append(subdomain)
        else:
            dict["subdomain_withoutdomain"].append(subdomain)
    return dict

def service_recognizer(scan_dict :dict) -> dict:
    #open the file with all the services in wordlists/tcp.csv
    #the csv file is in the format:
    """
    "protocol","port","description"
    "TCP",0,"Reserved"
    """
    #convert to dict in the format :
    """
    0: "Reserved"
    """
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
                if scan_dict[ip]["ports"][port]["service"] == None:
                    with open("wordlists/tcp.csv", "r") as file:
                        csv_reader = csv.reader(file)
                        for row in csv_reader:
                            if row[1] == port:
                                scan_dict[ip]["ports"][port]["service"] = row[2]
        except:
            pass
    return scan_dict
