from lib import custom_logger as cl
from lib import ip as ip_lib
from lib.generics import fqdn_scanner, ip_scanner, check_update
from lib.configuration import configuration
from lib.handler import handler
from lib.result import result
import datetime
from web.generator import main as web_generator
import os
import json

import tools.after_AS_scan.orc as after_AS_scan
import tools.AS_scan.orc as AS_scan
import argparse

logger = cl.logger


def main():
    print(
        """

    ███████                         █████████    █████████  ██████   ██████
  ███░░░░░███                      ███░░░░░███  ███░░░░░███░░██████ ██████ 
 ███     ░░███ ████████   ███████ ░███    ░███ ░███    ░░░  ░███░█████░███ 
░███      ░███░░███░░███ ███░░███ ░███████████ ░░█████████  ░███░░███ ░███ 
░███      ░███ ░███ ░░░ ░███ ░███ ░███░░░░░███  ░░░░░░░░███ ░███ ░░░  ░███ 
░░███     ███  ░███     ░███ ░███ ░███    ░███  ███    ░███ ░███      ░███ 
 ░░░███████░   █████    ░░███████ █████   █████░░█████████  █████     █████
   ░░░░░░░    ░░░░░      ░░░░░███░░░░░   ░░░░░  ░░░░░░░░░  ░░░░░     ░░░░░ 
                         ███ ░███                                          
                        ░░██████                                           
                         ░░░░░░                                            
                                                     
                                                     
                                                     """
    )
    start_time = datetime.datetime.now()
    date = start_time.strftime("%Y-%m-%d_%H-%M-%S")
    config = configuration()
    check_update(config)
    config.handler = handler(config)
    argpars = argparse.ArgumentParser()
    res = result()
    res.metadata["date"] = date
    resume = False
    argpars.add_argument("-d", "--domain", required=False, help="Domain to scan")
    argpars.add_argument("-ip", "--ip", required=False, help="IP to scan")
    argpars.add_argument(
        "-net",
        "--network",
        required=False,
        help="Network to scan, don't forget the CIDR (ex: 192.168.1.0/24)",
    )
    argpars.add_argument(
        "-R",
        "--recursive",
        required=False,
        default=1,
        type=int,
        help="Recursive scan, will rescan all the subdomains finds and go deeper as you want, default is 0",
    )
    argpars.add_argument(
        "--resume",
        required=False,
        default=False,
        type=str,
        help="Resume a scan from the json export. You can specify a tool (the last one to have finished), split with a ':' (ex: --resume exports/mydomain/date.json:nuclei) You can also use --resume exports/mydomain/date.json:export to just generate the html report",
    )
    args = argpars.parse_args()
    if not args.domain and not args.network and not args.ip and not args.resume:
        argpars.print_help()
        exit()
    if args.domain:
        name = args.domain
        res.metadata["input"] = name
        res.metadata["input_type"] = "domain"

    elif args.ip:
        name = args.ip
        res.metadata["input"] = name
        res.metadata["input_type"] = "ip"

    elif args.network:
        name = args.network
        res.metadata["input"] = name
        name = name.replace("/", "_")

    elif args.resume:
        name = res.metadata["input"]

    logger.info("[*] Starting tools to run before AS scan")

    if args.resume:
        if ":" in args.resume:
            # if more than one : in the resume argument
            if args.resume.count(":") > 1:
                # split on the last one
                resume_file = args.resume.rsplit(":", 1)[0]
                tool = args.resume.rsplit(":", 1)[1]
            else:
                tool = args.resume.split(":")[1]
                resume_file = args.resume.split(":")[0]
        if not ":" in args.resume:
            resume_file = args.resume
            if "last_tool" in res.metadata:
                tool = res.metadata["last_tool"]
            else:
                logger.error(f"[*] Error: no tool specified")
                exit(1)

        if tool != "export" and not os.path.exists(f"tools/{tool}.py"):
            logger.error(f"[*] Error: tool {tool} does not exist")
            exit(1)
        if not os.path.exists(resume_file):
            logger.error(f"[*] Error: export json {resume_file} does not exist")
            exit(1)
        if not os.path.isfile(resume_file):
            logger.error(f"[*] Error: export json {resume_file} is not a file")
            exit(1)
        try:
            data = json.load(open(resume_file, "r"))
            new = {}
            changed = False
            if not config.ip_trough_proxy and config.handler.there_is_proxy():
                olds = config.handler.remove_proxys()
            # pop metadata inside data and put it inside res.metadata
            res.metadata = data.pop("metadata")
            for ip in data:
                # replace the ip by the ip class
                new[ip_lib.ip(ip, config)] = data[ip]
            if changed:
                config.handler.add_proxys(olds)
            res.result = new
            res.printer()
            res.status()

            logger.info(f"[*] Resuming scan from {resume_file} with {tool}")
            config = configuration()
            config.handler = handler(config)
            resume = tool
        except:
            logger.error(f"[*] Error: {resume_file} is not in right format")

        if tool in config.config["TOOLS"]["AS_scan"]:
            AS_scan.main(config, res, name, resume)
            if res.metadata["input_type"] == "domain":
                fqdn_scanner(res.metadata["input"], config, res, args.recursive)
            elif res.metadata["input_type"] == "ip":
                ip_scanner(res.metadata["input"], config, res, args.recursive)
        else:
            resume = False
        logger.info("[*]")

    elif args.domain:
        AS_scan.main(config, res, name)
        fqdn_scanner(args.domain, config, res, args.recursive)

    elif args.ip:
        AS_scan.main(config, res, name)
        ip_scanner(args.ip, config, res, args.recursive)

    elif args.network:
        AS_scan.main(config, res, name)
        logger.info("[*] Scanning network")
        this_network = ip_lib.network(args.network)
        this_network.get_ip_from_network()
        for ip in this_network.ips:
            ip_scanner(ip, config, res, args.recursive)

    res.status()
    logger.info("[*] Attack Surface scan finished")
    res.printer()
    if not resume:
        after_AS_scan.main(config, res, name)
    else:
        if resume == "export":
            pass
        else:
            after_AS_scan.main(config, res, name, resume)
    end_time = datetime.datetime.now()
    logger.info(f"[*] Total time: {end_time - start_time}")
    res.metadata["time"] = str(end_time - start_time)
    # export the result
    try:
        if "tool" in locals() and tool != "export":
            res.export(name)
    except Exception as e:
        logger.error(f"Error while exporting the result: {e}")
    try:
        if "WEB" in config.config:
            if config.config["WEB"]["activate"]:
                html = web_generator(config, res)
                # put it inside export and the folder of the domain
                actual_date = datetime.datetime.now()
                if not os.path.exists(f"exports/{name}"):
                    os.makedirs(f"exports/{name}")
                with open(
                    f"exports/{name}/{actual_date.strftime('%Y-%m-%d_%H-%M-%S')}.html",
                    "w",
                ) as f:
                    f.write(html)
                    f.close()
                logger.info(
                    f"[*] Web page generated: exports/{name}/{actual_date.strftime('%Y-%m-%d_%H-%M-%S')}.html"
                )
        else:
            logger.info("[*] Web export option not activated in config file")

    except Exception as e:
        logger.error(f"Error while generating the web page: {e}")
        if args.resume:
            logger.warning(
                """
                [*] Most of the time when resuming, this is due to a tool that are activated
                    in the config file but their result are not in the export json file.
                    Check your config file and the export json file.
            """
            )


if __name__ == "__main__":
    main()
