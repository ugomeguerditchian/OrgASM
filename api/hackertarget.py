import lib.custom_logger as custom_logger
import lib.generics as gen
from lib.handler import handler

logger = custom_logger.logger


def main(domain, handler: handler, key: str):
    # get all the subdomain of the domain from hackertarget
    # the url is https://api.hackertarget.com/hostsearch/?q={domain}
    # key is the api key
    if key :
        url = (
            "https://api.hackertarget.com/hostsearch/?q="
            + domain
            + "&apikey="
            + key
        )
    else:
        url = "https://api.hackertarget.com/hostsearch/?q=" + domain
    try:
        response = handler.get(url, until_ok=True)._body.decode("utf-8")
        if response == "API count exceeded - Increase Quota with Membership":
            raise Exception("API")
        # split the response in linesr
        lines = response.split("\n")
        # get all the subdomains
        subdomains = []
        for line in lines:
            if line != "" and "*" not in line.split(",")[0]:
                subdomains.append(line.split(",")[0])
        # delete all the occurences in the list

        return subdomains
    except Exception as e:
        if e.args[0] == "API":
            logger.error(f"API count exceeded for hackertarget for {domain}")
        else:
            raise e
        return []
