import socket
import threading
def get_ip(domain):
    #get the ip address from the domain
    try :
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def detect_open_ports(ip, port_range):
    #detect all the open ports from the ip address
    #return a list of open ports
    open_ports = []
    for port in port_range:
        #print(f"Port scan for {ip} : " + str(round(range(1, port_range).index(port) / len(range(1,65535)) * 100, 2)) + "%", end="\r")
        #test if the port is open
        try:
            #try to connect to the port with a timeout of 0.1 second
            socket.create_connection((ip, port), 0.1)
            #if the connection is successful, add the port to the list
            open_ports.append(port)
        except:
            pass
    return open_ports

def divide_chunks(l, n):
     
    # looping till length l
    for i in range(0, len(l), n):
        yield l[i:i + n]

def detect_open_port_thread(ip :str, thread_number :int):
    #launch a thread for the def detect_open_ports
    #divde the port range by the number of thread, cut the range and launch a thread for each range
    #return a list of open ports
    total_port= 65535
    ranges= list(divide_chunks(range(1, total_port), total_port//thread_number))
    threads= []
    open_ports= []
    for port_range in ranges:
        #create a thread for each range
        thread= threading.Thread(target= lambda :open_ports.append(detect_open_ports(ip, port_range)))
        threads.append(thread)
        thread.start()
    for thread in threads:
        #wait for all the threads to finish
        thread.join()
    final_list= []
    for open_port in open_ports:
        #add all the open ports to a final list
        final_list+= open_port
    return final_list

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

def detect_banner(ip, port):
    #detect the banner from the ip address and the port
    #return the banner
    try:
        #try to connect to the port
        s = socket.create_connection((ip, port))
        #if the connection is successful, get the banner
        banner = s.recv(1024)
        return banner
    except:
        return None

def get_all_ip(subdomains: list, domain :str):
    #for all subdomains ping them and retrive their ip address
    #return a dict with ip address as key and subdomains as value
    """
    dict = {
        "ip"{
            subdomains: ["subdomain1", "subdomain2", "subdomain3"]
            }
    }
    """

    dict = {}
    for subdomain in subdomains:
        #ping the subdomain
        ip = get_ip(subdomain)
        if ip is not None:
            #if the subdomain has an ip address
            if ip in dict:
                #if the ip address is already in the dict, add the subdomain to the list
                dict[ip]["subdomains"].append(subdomain)
            else:
                #if the ip address is not in the dict, add the ip address to the dict
                dict[ip] = {"subdomains": [subdomain]}
        else:
            pass
    return dict