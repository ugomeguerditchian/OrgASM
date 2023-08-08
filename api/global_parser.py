import importlib
import pkgutil
import lib.custom_logger as custom_logger
from lib import generics as gen
from lib.configuration import configuration
import api

logger = custom_logger.logger


def main(domain: str, config: configuration) -> list:
    """
    This function is the entry point of the program. It takes a domain name and a configuration object as parameters.
    :param domain: The domain name to search for subdomains.
    :type domain: str
    :param config: The configuration object.
    :type config: configuration
    :return: A list of subdomains.
    :rtype: list
    """
    results = []
    # Get a list of all the modules in the api package
    for _, module_name, _ in pkgutil.walk_packages(api.__path__):
        if module_name in ["global_parser", "__init__"]:
            continue
        # Dynamically import the module
        module = importlib.import_module(f"api.{module_name}")
        try:
            # Call the main() function of the module
            data = config.config["API"]["mapper"][module_name]
            if not data["activate"]:
                logger.info(f"[*] {module_name} is deactivated")
                continue
            key = data["api_key"] or None
            logger.info(f"[*] Getting subdomains of {domain} from {module_name}")
            results += module.main(domain, config.handler, key)
            if len(results) == 0:
                logger.info(f"[*] No subdomains of {domain} found from {module_name}")
            else:
                # Remove duplicates and invalid subdomains
                results = list(set(results))
                logger.info(f"[*] {len(results)} subdomains of {domain} found")
        except Exception as e:
            logger.error(
                f"Impossible to get subdomains of {domain} from {module_name}: {e}"
            )
            continue
    return results
