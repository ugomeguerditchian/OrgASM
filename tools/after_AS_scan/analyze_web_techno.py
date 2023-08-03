import webtech
from concurrent.futures import ThreadPoolExecutor
from lib.ip import ip as ip_lib
from lib.result import result
import lib.handler as handler
import lib.generics as gen
import lib.custom_logger as custom_logger

logger = custom_logger.logger


def get_tech(url: str) -> dict:
    try:
        result = webtech.WebTech(options={"json": True}).start_from_url(url)
    except:
        try:
            result = webtech.WebTech(options={"json": True}).start_from_url(url)
        except:
            result = None
    return result


def main(config: gen.configuration, res: result):
    if not "analyze_web_techno" in config.config["TOOLS"]["after_AS_scan"]:
        logger.error("[*] Missing analyze_web_techno in TOOLS in config file")
        return
    this_tool_config = config.config["TOOLS"]["after_AS_scan"]["analyze_web_techno"]
    to_have = ["workers", "activate"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping analyze_web_techno")
        return

    for ip in res.result:
        logger.info(f"[*] Detecting web technologies on {ip.ip}")

        with ThreadPoolExecutor(max_workers=this_tool_config["workers"]) as executor:
            futures = {}
            if not "ports" in res.result[ip]:
                res.result[ip]["ports"] = {}
            for port in res.result[ip]["ports"]:
                futures.update(
                    {port: executor.submit(ip.handler.get, f"https://{ip.ip}:{port}")}
                )
            olds = []
            futures_2 = {}
            for port_, future in futures.items():
                if future.result():
                    olds.append(res.result[ip]["ports"][port_]["service"])
                    res.result[ip]["ports"][port_]["service"] = "web"
                for port in res.result[ip]["ports"]:
                    if res.result[ip]["ports"][port_]["service"] == "web":
                        futures_2.update(
                            {port: executor.submit(get_tech, f"https://{ip.ip}:{port}")}
                        )
            for old in olds:
                if old:
                    res.result[ip]["ports"][port_]["service"] = old
            for port, future in futures_2.items():
                if future.result():
                    res.result[ip]["ports"][port]["technologies"] = future.result()

            futures = {}
            for port in res.result[ip]["ports"]:
                futures.update(
                    {port: executor.submit(ip.handler.get, f"http://{ip.ip}:{port}")}
                )
            olds = []
            futures_2 = {}
            for port_, future in futures.items():
                if future.result():
                    olds.append(res.result[ip]["ports"][port_]["service"])
                    res.result[ip]["ports"][port_]["service"] = "web"
                for port in res.result[ip]["ports"]:
                    if res.result[ip]["ports"][port_]["service"] == "web":
                        futures_2.update(
                            {port: executor.submit(get_tech, f"http://{ip.ip}:{port}")}
                        )
            for old in olds:
                if old:
                    res.result[ip]["ports"][port_]["service"] = old
            for port, future in futures_2.items():
                if future.result():
                    res.result[ip]["ports"][port]["technologies"] = future.result()

            futures = {}
            for fqdn in res.result[ip]["fqdns"]:
                futures.update({fqdn: executor.submit(get_tech, f"https://{fqdn}")})
            for fqdn, future in futures.items():
                if future.result():
                    res.result[ip]["fqdns"][fqdn]["technologies"] = future.result()
            futures = {}
            for fqdn in res.result[ip]["fqdns"]:
                futures.update({fqdn: executor.submit(get_tech, f"http://{fqdn}")})
            for fqdn, future in futures.items():
                if future.result():
                    res.result[ip]["fqdns"][fqdn]["technologies"] = future.result()

    logger.info("[*] Detecting web port and technologies finished")
    return res
