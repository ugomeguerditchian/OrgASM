import socket

def get_ip(domain):
    #get the ip address from the domain
    try :
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def detect_open_ports(ip):
    #detect all the open ports from the ip address
    #return a list of open ports
    open_ports = []
    for port in range(1, 65535):
        #test if the port is open
        try:
            #try to connect to the port
            socket.create_connection((ip, port))
            #if the connection is successful, add the port to the list
            open_ports.append(port)
        except:
            pass
    return open_ports

def detect_service(ip, port):
    #detect the service from the ip address and the port
    #return the service
    try:
        #try to connect to the port
        socket.create_connection((ip, port))
        #if the connection is successful, get the service
        service = socket.getservbyport(port)
        return service
    except:
        return None

def get_all_ip(subdomains: list, domain :str):
    #for all subdomains ping them and retrive their ip address
    #return a dict with ip address as key and subdomains as value
    """
    dict = {
        "ip": ["subdomain1", "subdomain2", "subdomain3"]
    }
    """
    dict = {}
    for subdomain in subdomains:
        #get the ip address
        ip = get_ip(subdomain)
        #if the ip address is not None
        if ip != None:
            #if the ip address is not in the dict
            if ip not in dict:
                #add the ip address to the dict
                dict[ip] = []
            #add the subdomain to the dict
            dict[ip].append(subdomain)
    return dict