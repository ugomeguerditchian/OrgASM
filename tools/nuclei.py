import subprocess
import os
import lib.custom_logger as custom_logger
import time
from datetime import datetime
import json
from lib.result import result
import lib.generics as gen

logger = custom_logger.logger


def check_if_nuclei_installed() -> bool:
    # check if nuclei is installed by doing nuclei -h
    # return True if installed, False otherwise
    # use subprocess to run the command and don't show the output
    try:
        subprocess.run(
            ["nuclei", "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except:
        return False


def nuclei_scan(hosts: list, domain: str, vulnconf: str, headless=False) -> dict:
    # scan the hosts with nuclei
    # return the results
    # check if nuclei is installed
    logger.info("Checking if nuclei is installed...")
    if not check_if_nuclei_installed():
        logger.error("Nuclei is not installed")
        return None
    else:
        logger.info("Nuclei is installed")

    # create nuclei folder in project folder
    if not os.path.exists("nuclei"):
        os.mkdir("nuclei")

    # create a folder for the domain
    if not os.path.exists(f"nuclei/{domain}"):
        os.mkdir(f"nuclei/{domain}")

    # create a hosts.txt with one host per line
    with open(f"nuclei/{domain}/hosts.txt", "w") as f:
        for host in hosts:
            f.write(f"{host}\r")
        f.close()
        # parse the file and delete if line is empty
        with open(f"nuclei/{domain}/hosts.txt", "r") as f:
            lines = f.readlines()
            f.close()
        with open(f"nuclei/{domain}/hosts.txt", "w") as f:
            for line in lines:
                if line.strip("\r") != "":
                    f.write(line)
            f.close()

    # update nuclei don't show the output
    logger.info("Updating nuclei")
    subprocess.run(
        ["nuclei", "-update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    # update nuclei templates
    logger.info("Updating nuclei templates")
    subprocess.run(
        ["nuclei", "-ut"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # run nuclei and save the results in a json file
    # countdown to 5 seconds
    logger.info("Starting nuclei scan in 5 seconds")
    for i in range(5, 0, -1):
        logger.info(f"{i}...")
        time.sleep(1)
    actual_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if vulnconf:
        try:
            with open(vulnconf, "r") as f:
                f.close()
        except:
            logger.error("Error : Vuln config file not found")
            return None
        logger.info("Running nuclei with config file")
        os.system(
            f"nuclei -l nuclei/{domain}/hosts.txt -config {vulnconf} -json -o nuclei/{domain}/results.json"
        )
    else:
        if headless:
            os.system(
                f"nuclei -l nuclei/{domain}/hosts.txt -rl 500 -c 200 -bs 200 -hbs 200 -headc 200 -timeout 3 -page-timeout 3 -headless -jsonl -o nuclei/{domain}/results_{actual_time}.json"
            )
        else:
            os.system(
                f"nuclei -l nuclei/{domain}/hosts.txt -rl 500 -c 200 -bs 200 -hbs 200 -headc 200 -timeout 3 -page-timeout 3 -jsonl -o nuclei/{domain}/results_{actual_time}.json"
            )
    # read the output
    with open(f"nuclei/{domain}/results_{actual_time}.json", "r") as f:
        if f.read() == "":
            return None
        # each line is a json
        f.seek(0)
        results = []
        for line in f:
            results.append(json.loads(line))
        f.close()
    return results


def main(config: gen.configuration, res: result) -> dict:
    if not "nuclei" in config.config["TOOLS"]:
        logger.error("[*] Missing nuclei in TOOLS in config file")
        return
    this_tool_config = config.config["TOOLS"]["nuclei"]
    to_have = ["activate", "conf_file"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping nuclei")
        return

    logger.info("Running nuclei scan...")
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

    # domain is the fqdn with minmal len
    fqdns = []
    for ip in res.result:
        for fqdn in res.result[ip]["fqdns"]:
            fqdns.append(fqdn)
    if len(fqdns) == 0:
        logger.error("No FQDN provided for Nuclei to scan")
        return res.result
    domain = min(fqdns, key=len)
    if config.config["TOOLS"]["nuclei"]["headless_browser"]:
        headless = True
    else:
        headless = False
    nuclei_results = nuclei_scan(
        hosts_list, domain, this_tool_config["conf_file"], headless
    )
    logger.info("Nuclei scan finished")
    if nuclei_results:
        logger.info("Parsing nuclei results...")
        # in ip_dict add vulns key and add the nuclei results
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
        # add vulns key to subdomains and add the nuclei results, split the 'https://' from the subdomain

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
    return res.result
