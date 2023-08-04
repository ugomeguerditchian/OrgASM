import os
from concurrent.futures import ThreadPoolExecutor
import lib.custom_logger as custom_logger
import lib.ip as ip_lib
from lib.handler import handler
from lib.result import result
from lib.domain import domain
import tools.AS_scan.orc as AS_scan
from lib.configuration import configuration
from tqdm import tqdm
import time
import json
import git
import pyzipper

import requests

logger = custom_logger.logger


def clear_screen():
    """Clear the screen"""
    os.system("cls" if os.name == "nt" else "clear")


def fqdn_scanner(
    main_fqdn: str, config: configuration, res: result, recursive: int = 0
):
    logger.info("[*] Scanning fqdn {}".format(main_fqdn))
    main_domain = domain(main_fqdn, config)
    if main_domain.ip == "Dead":
        res.add_dead(main_domain.name)
    else:
        if not res.check_if_ip_in_res(main_domain.ip):
            this_ip = ip_lib.ip(main_domain.ip, config)
        else:
            this_ip = res.get_ip_in_res(main_domain.ip)

        res.add_fqdn(this_ip, main_domain.name)
    subs = main_domain.get_subs(config.ip_trough_proxy)
    # remove duplicates
    subs = list(dict.fromkeys(subs))
    futures_scope = {}
    if config.is_there_scope():
        with tqdm(total=len(subs), desc="Scoping subdomains", ncols=100) as progress:
            with ThreadPoolExecutor(max_workers=config.api_max_workers) as executor:
                for fqdn in subs:
                    futures_scope[fqdn] = executor.submit(
                        config.is_in_scope, fqdn, mode="FQDNs"
                    )
                for fqdn in subs:
                    futures_scope[fqdn] = futures_scope[fqdn].result()
                    progress.update()

    with ThreadPoolExecutor(max_workers=config.api_max_workers) as executor:
        futures_domain = {fqdn: executor.submit(domain, fqdn, config) for fqdn in subs}

    for fqdn in tqdm(subs, desc="Processing subdomains", ncols=100):
        if fqdn == "localhost" or config.is_there_scope() and not futures_scope[fqdn]:
            continue
        sub_domain = futures_domain[fqdn].result()
        if sub_domain.ip == "Dead":
            res.add_dead(sub_domain.name)
        else:
            if not res.check_if_fqdn_in_res(sub_domain.name):
                if not res.check_if_ip_in_res(sub_domain.ip):
                    this_ip = ip_lib.ip(sub_domain.ip, config)
                else:
                    this_ip = res.get_ip_in_res(sub_domain.ip)
                res.add_fqdn(this_ip, sub_domain.name)

    if recursive > 0:
        res.status()
        logger.info("[*] Recursive scan")
        subs = []
        old_subs = [main_fqdn]
        for i in range(recursive):
            with ThreadPoolExecutor(max_workers=config.api_max_workers) as executor:
                futures_get_subs = []
                futures_domain_recursive = {}
                for ip in res.result :
                    if config.is_there_scope() and not config.is_in_scope(
                        str(ip.ip), mode="IPs"
                    ):
                        continue
                    for fqdn in res.result[ip]["fqdns"]:
                        if (
                            fqdn not in old_subs
                            or config.is_there_scope()
                            and config.is_in_scope(fqdn, mode="FQDNs")
                            and fqdn not in old_subs
                        ):
                            AS_scan.main(config, res, name=fqdn, recursive=True)
                            old_subs.append(fqdn)
                            logger.info(f"[*] Scanning subdomain {fqdn}")
                            sub_domain_future = executor.submit(domain, fqdn, config)
                            futures_domain_recursive[fqdn] = sub_domain_future
                            futures_get_subs.append(
                                executor.submit(
                                    sub_domain_future.result().get_subs,
                                    config.ip_trough_proxy,
                                )
                            )

                logger.info(
                    "[*] Waiting for {} threads to finish to getting subs".format(
                        len(futures_get_subs)
                    )
                )
                for future in futures_get_subs:
                    subs += future.result()
                logger.info(
                    "[*] {} subs found (may contain duplicates)".format(len(subs))
                )
                # remove duplicates
                subs = list(dict.fromkeys(subs))
                for fqdn in tqdm(subs, desc="Processing subdomains", ncols=100):
                    if (
                        fqdn == "localhost"
                        or config.is_there_scope()
                        or fqdn not in futures_domain_recursive
                    ):
                        continue
                    sub_domain = futures_domain_recursive[fqdn].result()
                    if sub_domain.ip == "Dead":
                        res.add_dead(sub_domain.name)
                    else:
                        if not res.check_if_fqdn_in_res(sub_domain.name):
                            if not res.check_if_ip_in_res(sub_domain.ip):
                                this_ip = ip_lib.ip(sub_domain.ip, config)
                            else:
                                this_ip = res.get_ip_in_res(sub_domain.ip)
                            res.add_fqdn(this_ip, sub_domain.name)

            logger.info("[*] Recursive {} finished".format(i + 1))
            res.status()


def ip_scanner(ip: str, config: configuration, res: result, recursive: int = 0):
    ip_obj = ip_lib.ip(ip, config)
    res.add_ip(ip_obj)
    if config.ip_get_fqdn:
        if not config.get_fqdn_trough_proxy and config.handler.there_is_proxy():
            logger.info("[*] Deactivating proxy")
            old_handler = ip_obj.handler
            ip_obj.handler = handler(config)
            logger.info(f"[*] Getting FQDN for {str(ip_obj.ip)}")
            fqdn = ip_obj.try_get_fqdn()
            if not fqdn:
                fqdn = ip_obj.get_fqdns()
                if fqdn:
                    fqdn = fqdn[0]
            logger.info("[*] Reactivating proxy")
            ip_obj.handler = old_handler
        else:
            logger.info(f"[*] Getting FQDN for {str(ip_obj.ip)}")
            fqdn = ip_obj.try_get_fqdn()
            if not fqdn:
                fqdn = ip_obj.get_fqdns()
                if fqdn:
                    fqdn = fqdn[0]

        if (
            fqdn
            and config.is_there_scope()
            and config.is_in_scope(fqdn, mode="FQDNs")
            or fqdn
            and not config.is_there_scope()
        ):
            res.add_fqdn(ip_obj, fqdn)
            if config.find_subs:
                logger.info("[*] Finding subdomains")
                fqdn_scanner(fqdn, config, res, recursive)


def is_to_update(last_update, recurence, how_often):
    """Check if a file needs to be updated
    last_update : date of last update
    recurence : can contains "secondes", "minutes", "hours", "days"
    how_often : can contains a number
    """
    if recurence == "seconds":
        if time.time() - time.mktime(time.strptime(last_update, "%d/%m/%Y %H:%M:%S")) > int(
            how_often
        ):
            return True
    elif recurence == "minutes":
        if time.time() - time.mktime(time.strptime(last_update, "%d/%m/%Y %H:%M:%S")) > int(
            how_often
        ) * 60:
            return True
    elif recurence == "hours":
        if time.time() - time.mktime(time.strptime(last_update, "%d/%m/%Y %H:%M:%S")) > int(
            how_often
        ) * 3600:
            return True
    elif recurence == "days":
        if time.time() - time.mktime(time.strptime(last_update, "%d/%m/%Y %H:%M:%S")) > int(
            how_often
        ) * 86400:
            return True
    else:
        logger.error("Wrong recurence")
        return False


def check_update(config: configuration):
    logger.info("Checking for update...")
    if not os.path.isfile("manifest.json"):
        logger.error("manifest.json not found")
        logger.warning(
            "There is certainly an update available go on website : https://github.com/ugomeguerditchian/OrgASM"
        )
        return
    try:
        with open("manifest.json", "r") as f:
            manifest = json.load(f)
        version = manifest["version"]
        url = f"https://raw.githubusercontent.com/ugomeguerditchian/OrgASM/main/manifest.json"
        try:
            response = requests.get(url).json()
            if response["version"] == version:
                logger.info("You are up to date")
            elif response["version"] > version:
                logger.warning("Update available")
                if git.cmd.Git().version() and not config.config.get("dev_mode", False):
                    answer = input("Do you want to update? (y/n) : ")
                    if answer.lower() == "y":
                        repo = git.Repo(".")
                        repo.remotes.origin.pull()
                        logger.info("Update successful")
                        exit(1)
                    elif answer.lower() == "n":
                        pass
                    else:
                        logger.error("Wrong answer, aborting")
                        pass
                else:
                    logger.warning("Git is not installed")
                    answer = input(
                        "Do you want to download the new version from GitHub? (y/n) : "
                    )
                    if answer.lower() == "y" and not config.config.get(
                        "dev_mode", False
                    ):
                        url = f"https://github.com/ugomeguerditchian/OrgASM/archive/refs/tags/{response['version']}.zip"
                        r = requests.get(url)
                        with pyzipper.AESZipFile(
                            "new_version.zip",
                            "w",
                            compression=pyzipper.ZIP_DEFLATED,
                            encryption=pyzipper.WZ_AES,
                        ) as zf:
                            zf.writestr("new_version.zip", r.content)
                        with pyzipper.AESZipFile("new_version.zip") as zf:
                            zf.extractall()
                        os.remove("new_version.zip")
                        logger.info("Update successful")
                        exit(1)
            elif response["version"] < version:
                logger.info("Wtf bro, you are in the future")
        except:
            logger.error("Impossible to get url to check for update")
            pass
    except Exception as e:
        logger.error(f"Impossible to check for update : {e}")
    
    # now update file in config
    to_update = config.config["UPDATE"]

    if not os.path.isfile("manifest_update.json"):
        #create manifest_update.json
        manifest_tools = {}
        for line in to_update:
            # format : path_to_file : url
            path = list(line.keys())[0]
            manifest_tools[path] = "01/01/2020 00:00:00"
        with open("manifest_update.json", "w") as f:
            json.dump(manifest_tools, f)
    #reset cursor
    manifest_update = json.loads(open("manifest_update.json", "r").read())
    for line in to_update:
        # format : path_to_file : url
        path = list(line.keys())[0]
        url = line[path][0]
        recurence = line[path][1].split(":")[
            1
        ]  # can contains "secondes", "minutes", "hours", "days"
        how_often = line[path][1].split(":")[0]  # can contains a number
        if is_to_update(manifest_update[path], recurence, how_often):
            try:
                response = requests.get(url)
            except:
                logger.error(f"Impossible to update {path}")
                continue
            with open(path, "w") as f:
                f.write(response.text)
            logger.info(f"Update {path} successful")
            manifest_update[path] = time.strftime("%d/%m/%Y %H:%M:%S")
    with open("manifest_update.json", "w") as f:
        json.dump(manifest_update, f)
   