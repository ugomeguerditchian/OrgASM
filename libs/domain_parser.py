import requests
from pythonping import ping
from concurrent.futures import ThreadPoolExecutor
def detect_redirect(url: str) -> bool:
    try:
        response = requests.get("https://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
    except:
        try :
            response = requests.get("http://"+url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
        except:
            return None
    if response.history:
        return True
    else:
        return False

def detect_redirect_with_thread_limit(subdomains: list, thread_number: int) -> list:
    real_subdomains = []
    subdomains_with_redirect = []
    with ThreadPoolExecutor(thread_number) as executor:
        results = executor.map(detect_redirect, subdomains)
        for subdomain, is_redirect in zip(subdomains, results):
            if is_redirect:
                print(f'> {subdomain} is a redirect')
                subdomains_with_redirect.append(subdomain)
            else:
                print(f'> {subdomain} is not a redirect')
                real_subdomains.append(subdomain)
    return real_subdomains, subdomains_with_redirect


def check_up(url: str) -> bool:
    try:
        response = requests.get(url, headers={'User-Agent': 'Google Chrome'}, timeout=20)
    except:
        # Use ping to check if the server is up
        try:
            ping(url, timeout=1)
            return True
        except Exception as e:
            print(e)
            return False
    if response.status_code == 200:
        return True
    else:
        return False

if __name__ == "__main__":
    print(detect_redirect("https://orangecyberdefense.com"))
    print(check_up("https://orangecyberdefense.com"))
    print(check_up("https://content.pizza.benoit.fage.fr"))