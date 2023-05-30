import lib.custom_logger as custom_logger
from lib import generics as gen
from lib.configuration import configuration
from api import *
import os

logger = custom_logger.logger


def main(domain: str, config: configuration):
    # get all the lib in the api folder and call the main function
    results = []
    for os_file in os.listdir(os.path.dirname(__file__)):
        if os_file.endswith(".py") and os_file not in [
            "__init__.py",
            "global_parser.py",
        ]:
            try:
                try:
                    data = config.config["API"]["mapper"][os_file.split(".")[0]]
                    if not data["activate"]:
                        logger.info(f"[*] {os_file} is deactivated")
                        continue
                    key = data["api_key"]
                    if key == "":
                        key == None
                except:
                    logger.info(
                        "[*] This API seems to not appear in the config file or no key is provided"
                    )
                    logger.info("[*] Continuing without API key")
                    key = None
                logger.info(f"[*] Getting subdomains of {domain} from {os_file}")
                results += eval(
                    os_file.split(".")[0] + ".main(domain, config.handler, key)"
                )
                if len(results) == 0:
                    warn = ""
                    logger.info(f"[*] No subdomains of {domain} found from {os_file}")
                else:
                    # remove duplicates
                    results = list(dict.fromkeys(results))
                    logger.info(f"[*] {len(results)} subdomains of {domain} found")
            except Exception as e:
                logger.error(f"Impossible to get subdomains of {domain} from {os_file}")
                continue
    return results
