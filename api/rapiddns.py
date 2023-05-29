import lib.custom_logger as custom_logger
import lib.generics as gen
from lib.handler import handler
from bs4 import BeautifulSoup

logger = custom_logger.logger


def main(domain, handler: handler, key: str):
    # get all the subdomain of the domain from rapiddns
    # https://rapiddns.io/subdomain/{domain}?full=1&down=1

    url = "https://rapiddns.io/subdomain/" + domain + "?full=1&down=1"
    try:
        response = handler.get(url, until_ok=False)
    except Exception as e:
        raise e
    soup = BeautifulSoup(response._body.decode("utf-8"), "html.parser")
    table = soup.find("table", {"class": "table table-hover table-bordered"})
    if table is None:
        return []
    subdomains = []
    for row in table.findAll("tr"):
        subdomain = row.findAll("td")[1].find("a")
        if subdomain is not None:
            subdomains.append(subdomain.text)
    return subdomains
