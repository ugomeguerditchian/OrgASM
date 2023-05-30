import lib.custom_logger as custom_logger
import lib.generics as gen
from lib.handler import handler
import json

logger = custom_logger.logger


def main(domain, handler: handler, key: str):
    # get all the subdomain of the domain from anubisd
    # the url is https://jonlu.ca/anubis/subdomains/{domain}
    """
    example :
    ["secure.jonlu.ca","mail.jonlu.ca","wiki.jonlu.ca","blog.jonlu.ca","matomo.jonlu.ca","hostmaster.jonlu.ca","box.jonlu.ca","stats.jonlu.ca"]
    """
    subdomains = []
    url = f"https://jonlu.ca/anubis/subdomains/{domain}"
    response = handler.get(url, until_ok=False)._body.decode("utf-8")
    response = json.loads(response)
    for i in response:
        if i == "error" or not "." in i or "*" in i:
            continue
        subdomains.append(i)
    return subdomains
