import subprocess
import os
import lib.custom_logger as custom_logger
import time
from datetime import datetime
import json
from lib.result import result
import lib.generics as gen
from typing import Dict, List, Union

logger = custom_logger.logger


def check_if_nuclei_installed() -> bool:
    """
    Check if Nuclei is installed by running the command "nuclei -h".
    Return True if installed, False otherwise.
    """
    try:
        subprocess.check_call(
            ["nuclei", "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False


def nuclei_scan(hosts: list, domain: str, vulnconf: str, headless=False) -> dict:
    """
    Scan the hosts with Nuclei and return the results as a list of dictionaries.
    :param hosts: A list of hosts to scan.
    :param domain: The domain name to use for the scan.
    :param vulnconf: The path to the Nuclei config file to use for the scan.
    :param headless: Whether to run the scan in headless mode or not.
    :return: A list of dictionaries representing the scan results.
    """
    # Check if Nuclei is installed
    logger.info("Checking if Nuclei is installed...")
    if not check_if_nuclei_installed():
        logger.error("Nuclei is not installed")
        return None
    else:
        logger.info("Nuclei is installed")

    # Create Nuclei folder in project folder
    os.makedirs("nuclei", exist_ok=True)

    # Create a folder for the domain
    os.makedirs(f"nuclei/{domain}", exist_ok=True)

    # Create a hosts.txt file with one host per line
    with open(f"nuclei/{domain}/hosts.txt", "w") as f:
        for host in hosts:
            f.write(f"{host}\n")
    # Parse the file and delete empty lines
    with open(f"nuclei/{domain}/hosts.txt", "r") as f:
        lines = f.readlines()
    with open(f"nuclei/{domain}/hosts.txt", "w") as f:
        for line in lines:
            if line.strip() != "":
                f.write(line)

    # Update Nuclei
    logger.info("Updating Nuclei")
    subprocess.run(
        ["nuclei", "-update"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    # Update Nuclei templates
    logger.info("Updating Nuclei templates")
    subprocess.run(
        ["nuclei", "-ut"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )

    # Run Nuclei and save the results in a JSON file
    logger.info("Starting Nuclei scan...")
    actual_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if vulnconf:
        if not os.path.isfile(vulnconf):
            logger.error("Error: Vuln config file not found")
            return None
        logger.info("Running Nuclei with config file")
        os.system(
            f"nuclei -l nuclei/{domain}/hosts.txt -config {vulnconf} -json -o nuclei/{domain}/results.json"
        )
    else:
        args = [
            f"nuclei -l nuclei/{domain}/hosts.txt -rl 500 -c 200 -bs 200 -hbs 200 -headc 200 -timeout 3 -page-timeout 3 -jsonl -o nuclei/{domain}/results_{actual_time}.json"
        ]
        if headless:
            args.append("-headless")
        os.system(" ".join(args))

    # Read the output
    results = []
    while True:
        time.sleep(1)
        if os.path.isfile(f"nuclei/{domain}/results_{actual_time}.json"):
            with open(f"nuclei/{domain}/results_{actual_time}.json", "r") as f:
                for line in f:
                    results.append(json.loads(line))
            break

    return results


def main(config: gen.configuration, res: result) -> Dict:
    """
    This function is the main function that runs the nuclei scan.
    It takes in the configuration and result objects and returns the result object with the nuclei scan results added.
    """
    # Check if nuclei is in the config file
    if not "nuclei" in config.config["TOOLS"]["after_AS_scan"]:
        logger.error("[*] Missing nuclei in TOOLS in config file")
        return

    # Check if the necessary parameters are in the nuclei config
    this_tool_config = config.config["TOOLS"]["after_AS_scan"]["nuclei"]
    to_have = ["activate", "conf_file"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return

    # Check if nuclei is activated
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping nuclei")
        return

    # Get a list of all hosts to scan
    hosts_list = get_hosts_list(res)

    # Get the domain to scan
    domain = get_domain(res, config)

    # Check if headless browser is enabled
    headless = this_tool_config["headless_browser"]

    # Run the nuclei scan
    nuclei_results = nuclei_scan(
        hosts_list, domain, this_tool_config["conf_file"], headless
    )

    # Parse the nuclei results and add them to the result object
    parse_nuclei_results(nuclei_results, res)

    return res.result


def get_hosts_list(res: result) -> List[str]:
    """
    This function takes in the result object and returns a list of all hosts to scan.
    """
    hosts_list = []
    for ip in res.result:
        hosts_list.append(str(ip.ip))
        for fqdn in res.result[ip]["fqdns"]:
            hosts_list.append("https://" + fqdn)
            hosts_list.append("http://" + fqdn)
        if not "ports" in res.result[ip]:
            res.result[ip]["ports"] = {}
        for port in res.result[ip]["ports"]:
            if (
                type(res.result[ip]["ports"]) == dict
                and res.result[ip]["ports"][port] == "web"
            ):
                hosts_list.append("https://" + str(ip.ip) + ":" + str(port))
                hosts_list.append("http://" + str(ip.ip) + ":" + str(port))
    return hosts_list


def get_domain(res: result, config: gen.configuration) -> str:
    """
    This function takes in the result and configuration objects and returns the domain to scan.
    """
    fqdns = []
    for ip in res.result:
        for fqdn in res.result[ip]["fqdns"]:
            fqdns.append(fqdn)
    if len(fqdns) == 0:
        logger.error("No FQDN provided for Nuclei to scan")
        return res.result
    domain = min(fqdns, key=len)
    if config.config["TOOLS"]["after_AS_scan"]["nuclei"]["headless_browser"]:
        headless = True
    else:
        headless = False
    return domain


def parse_nuclei_results(
    nuclei_results: List[Dict[str, Union[str, List[str]]]], res: result
) -> None:
    """
    This function takes in the nuclei scan results and the result object and adds the nuclei results to the result object.
    """
    if nuclei_results:
        logger.info("Parsing nuclei results...")

        # Add nuclei results to IP addresses
        for ip in res.result:
            res.result[ip]["vulns"] = []
            for result_ in nuclei_results:
                if result_["host"][-1] == ".":
                    result_["host"] = result_["host"][:-1]
                if (
                    result_["host"] == str(ip.ip)
                    or result_["matched-at"] == str(ip.ip)
                    or result_["host"] == "https://" + str(ip.ip)
                    or result_["host"] == "http://" + str(ip.ip)
                    and result_ not in res.result[ip]["vulns"]
                ):
                    res.result[ip]["vulns"].append(result_)

        # Add nuclei results to subdomains
        for ip in res.result:
            for fqdn in res.result[ip]["fqdns"]:
                res.result[ip]["fqdns"][fqdn]["vulns"] = []
                for result_ in nuclei_results:
                    if result_["host"][-1] == ".":
                        result_["host"] = result_["host"][:-1]
                    if (
                        result_["host"] == fqdn
                        or result_["matched-at"] == fqdn
                        or result_["host"] == "https://" + fqdn
                        or result_["host"] == "http://" + fqdn
                        and result_ not in res.result[ip]["fqdns"][fqdn]["vulns"]
                    ):
                        res.result[ip]["fqdns"][fqdn]["vulns"].append(result_)

        logger.info("Nuclei results parsed")
