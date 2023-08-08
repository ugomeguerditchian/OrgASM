import lib.custom_logger as custom_logger
import lib.generics as gen
from lib.handler import handler

logger = custom_logger.logger


def main(domain: str, handler: handler, key: str = "") -> list:
    """
    Get all the subdomains of the domain from hackertarget.
    The url is https://api.hackertarget.com/hostsearch/?q={domain}.
    :param domain: The domain to search for subdomains.
    :param handler: The handler to use for the request.
    :param key: The API key to use for the request.
    :return: A list of subdomains.
    """
    # Construct the URL for the API request.
    if key:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}&apikey={key}"
    else:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        # Make the API request and decode the response.
        response = handler.get(url, until_ok=True)._body.decode("utf-8")
        if response == "API count exceeded - Increase Quota with Membership":
            raise Exception("API")
        # Split the response into lines.
        lines = response.split("\n")
        # Get all the subdomains.
        subdomains = [
            line.split(",")[0]
            for line in lines
            if line != "" and "*" not in line.split(",")[0]
        ]
        return subdomains
    except Exception as e:
        if e.args[0] == "API":
            logger.error(f"API count exceeded for hackertarget for {domain}")
        else:
            raise e
        return []
