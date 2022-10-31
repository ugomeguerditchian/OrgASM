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