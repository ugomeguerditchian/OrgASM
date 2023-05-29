import lib.custom_logger as custom_logger
from lib.handler import handler
import lib.generics as gen
import json

logger = custom_logger.logger


def main(domain, handler: handler, key: str):
    # get all the subdomain of the domain from alienvault
    # url https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
    url = (
        "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns"
    )
    response = handler.get(url, until_ok=True)._body.decode("utf-8")
    # response is a json format
    # convert response.text in json
    json_data = json.loads(response)
    # get all the hostname
    subdomains = []
    for i in json_data["passive_dns"]:
        try:
            if "*" not in subdomains.append(i["hostname"]):
                subdomains.append(i["hostname"])
        except:
            pass
    return subdomains
