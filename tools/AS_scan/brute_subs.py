import dns.resolver
from tqdm import tqdm
import concurrent.futures
from lib.ip import ip as ip_lib
from lib.result import result
import lib.generics as gen
import lib.custom_logger as custom_logger
import time
import uuid
logger = custom_logger.logger

ips = set()
def is_wildcard(fqdn: str) -> bool:
    """
    Checks if the fqdn is a wildcard.

    :param fqdn: A string representing the fully qualified domain name.
    :return: A boolean indicating if the fqdn is a wildcard.
    """
    try:
        random_subdomain = str(uuid.uuid4())
        answer = dns.resolver.resolve(random_subdomain + "." + fqdn)
        if answer:
            # Test 100 random subdomains and store the ips inside ips set
            for i in range(100):
                random_subdomain = str(uuid.uuid4())
                answer = dns.resolver.resolve(random_subdomain + "." + fqdn)
                if answer:
                    ips.add(str(answer[0]))
            return True
        else:
            return False
        
    except:
        return False
def resolve_and_store(
    resolver: dns.resolver.Resolver,
    subdomain: str,
    fqdn: str,
    config: gen.configuration,
    res: result,
    pbar: tqdm,
    wildcard: bool = False,
) -> None:
    """
    Resolves the subdomain and stores the result inside res.result.

    :param resolver: A dns.resolver.Resolver object used to resolve the subdomain.
    :param subdomain: A string representing the subdomain to be resolved.
    :param fqdn: A string representing the fully qualified domain name.
    :param config: A gen.configuration object containing the configuration settings.
    :param res: A result object used to store the results.
    :param pbar: A tqdm object used to display the progress bar.
    """
    try:
        answer = resolver.resolve(subdomain + "." + fqdn)
        ip = str(answer[0])
        if ip in ips and wildcard:
            return
        name = str(answer.qname)
        ip = ip_lib.ip(ip, config)
        res.add_fqdn(ip, name)
    except:
        pass
    finally:
        pbar.update(1)


def main(config: gen.configuration, res: result, name: str) -> result:
    """
    Main function for bruteforcing subdomains.

    :param config: A gen.configuration object containing the configuration settings.
    :param res: A result object used to store the results.
    :param name: A string representing the domain name to be bruteforced.
    :return: A result object containing the results of the bruteforcing.
    """
    if not "brute_subs" in config.config["TOOLS"]["AS_scan"]:
        logger.error("[*] Missing brute_subs in TOOLS in config file")
        return
    this_tool_config = config.config["TOOLS"]["AS_scan"]["brute_subs"]
    to_have = ["workers", "wordlist_name", "resolver_name"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping brute_subs")
        return
    logger.info(f"[*] Bruteforcing subdomains for {name}")
    wildcard = False
    if is_wildcard(name):
        logger.info(f"[*] {name} is a wildcard")
        wildcard = True
        
    # get wordlist inside tools/worldlists
    wordlist = f"tools/wordlists/{this_tool_config['wordlist_name']}"
    # get resolver inside tools/resolvers
    resolver_file = f"tools/resolvers/{this_tool_config['resolver_name']}"
    fqdn = name
    resolver = dns.resolver.Resolver()
    resolver_data = open(resolver_file).read().splitlines()
    # store all matched subdomains inside res.result, with the ip class as key
    resolver.nameservers = resolver_data
    start_time = time.time()

    with open(wordlist) as f:
        subdomains = {line.strip() for line in f}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=this_tool_config["workers"]
        ) as executor:
            with tqdm(total=len(subdomains), leave=False) as pbar:
                futures = [
                    executor.submit(
                        resolve_and_store, resolver, subdomain, fqdn, config, res, pbar, wildcard
                    )
                    for subdomain in subdomains
                ]
                concurrent.futures.wait(futures)

    logger.info(
        f"[*] Bruteforcing subdomains finished in {(time.time() - start_time)/60} minutes"
    )
    return res
