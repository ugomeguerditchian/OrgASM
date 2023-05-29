import lib.custom_logger as custom_logger
import lib.generics as gen
from lib.handler import handler
import json

logger = custom_logger.logger


def main(domain, handler: handler, key: str):
    # get all the subdomain of the domain from crtsh
    url = f"https://crt.sh/?q={domain}&output=json"
    response = handler.get(url, until_ok=True)._body.decode("utf-8")
    # response is a json format
    # convert response.text in json
    json_data = json.loads(response)
    # get all the common_name and name_value
    subdomains = []
    for item in json_data:
        subdomains.append(item["common_name"])
        # split name_value in lines
        lines = item["name_value"].split("\n")
        for line in lines:
            if line != "" and "*" not in line:
                subdomains.append(line)

    return subdomains
