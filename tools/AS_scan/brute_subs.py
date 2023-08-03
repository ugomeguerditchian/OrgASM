import dns.resolver
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from lib.ip import ip as ip_lib
from lib.result import result
import lib.generics as gen
import lib.custom_logger as custom_logger
import time

logger = custom_logger.logger


def main(config: gen.configuration, res: result, name: str):
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

    # get wordlist inside tools/worldlists
    wordlist = f"tools/wordlists/{this_tool_config['wordlist_name']}"
    # get resolver inside tools/resolvers
    resolver_file = f"tools/resolvers/{this_tool_config['resolver_name']}"
    fqdn = name
    resolver = dns.resolver.Resolver()
    resolver_data = open(resolver_file).read().splitlines()
    # store all matched subdomains inside res.result, with the ip class as key
    resolver.nameservers = resolver_data

    def resolve_and_store(subdomain):
        # resolve and store inside res.result
        try:
            answer = resolver.resolve(subdomain + "." + fqdn)
            ip = str(answer[0])
            name = str(answer.qname)
            ip = ip_lib.ip(ip, config)
            res.add_fqdn(ip, name)
        except:
            pass

    logger.info("[*] Bruteforcing subdomains")
    start_time = time.time()
    with open(wordlist) as f:
        subdomains = [line.strip() for line in f]
        with ThreadPoolExecutor(max_workers=this_tool_config["workers"]) as executor:
            list(
                tqdm(executor.map(resolve_and_store, subdomains), total=len(subdomains))
            )
    logger.info(
        f"[*] Bruteforcing subdomains finished in {(time.time() - start_time)/60} minutes"
    )
    return res
