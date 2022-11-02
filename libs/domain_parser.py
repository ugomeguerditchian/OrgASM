import requests
from pythonping import ping
def detect_redirect(url: str) -> bool:
    try:
        response = requests.get(url, headers={'User-Agent': 'Google Chrome'}, timeout=1)
    except:
        return None
    if response.history:
        return True
    else:
        return False

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