import requests
from pythonping import ping
from concurrent.futures import ThreadPoolExecutor
def detect_redirect(url: str) -> bool:
    if check_up(url) :
        try:
            
                response = requests.get("https://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
        except:
            try :
                if check_up(url) :
                    response = requests.get("http://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
            except:
                return False
        if response.history:
            #split response.url to get the domain
            url_redirected= response.url.split("//")[1]
            domain = url_redirected.split("/")[0]
            if url_redirected == url:
                return False
            return domain
        else:
            return False
    else :
        return "dead"
def detect_redirect_with_thread_limit(subdomains: list, thread_number: int) -> list:
    real_subdomains = []
    subdomains_with_redirect = []
    dead_subdomains = []
    with ThreadPoolExecutor(thread_number) as executor:
        results = executor.map(detect_redirect, subdomains)
        for subdomain, is_redirect in zip(subdomains, results):
            if is_redirect == True:
                if is_redirect not in subdomains and is_redirect != "" :
                    real_subdomains.append(is_redirect)
                    #print(f'> {subdomain} is a redirect')
                subdomains_with_redirect.append(subdomain)
            elif is_redirect == None:
                pass
            elif is_redirect == "dead":
                dead_subdomains.append(subdomain)
            else:
                #print(f'> {subdomain} is not a redirect')
                real_subdomains.append(subdomain)
    return real_subdomains, subdomains_with_redirect, dead_subdomains


def check_up(url: str) -> bool:
    try:
        response = requests.get(url, headers={'User-Agent': 'Google Chrome'}, timeout=3)
    except:
        # Use ping to check if the server is up
        try:
            ping(url, timeout=1)
            return True
        except Exception as e:
            #print(e)
            return False
    if response.status_code == 200:
        return True
    else:
        return False

if __name__ == "__main__":
    print(check_up("info.orangecyberdefense.com"))
    print(detect_redirect("info.orangecyberdefense.com"))
    # print(check_up("https://content.pizza.benoit.fage.fr"))