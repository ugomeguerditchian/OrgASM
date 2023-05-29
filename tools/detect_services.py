from lib.ip import ip as ip_lib
from lib.result import result
import lib.generics as gen
import lib.custom_logger as custom_logger
from concurrent.futures import ThreadPoolExecutor

logger = custom_logger.logger


def main(config: gen.configuration, res: result):
    if not "detect_services" in config.config["TOOLS"]:
        logger.error("[*] Missing detect_services in TOOLS in config file")
        return
    this_tool_config = config.config["TOOLS"]["detect_services"]
    to_have = ["workers", "activate"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping detect_services")
        return

    logger.info("[*] Detecting services")
    changed = False
    if not config.ip_trough_proxy and config.handler.there_is_proxy():
        logger.info("[*] Disabling proxy for services detection")
        olds = config.handler.remove_proxys()
    for ip in res.result:
        logger.info(f"[*] Detecting services on {ip.ip}")
        if ip.status:
            futures = []
            with ThreadPoolExecutor(
                max_workers=this_tool_config["workers"]
            ) as executor:
                for port in res.result[ip]["ports"]:
                    futures.append(executor.submit(ip.detect_service, port))
            for future in futures:
                if future.result()["service"]:
                    res.result[ip]["ports"][future.result()["port"]][
                        "service"
                    ] = future.result()["service"]

    logger.info("[*] Detecting services finished")
    if changed:
        logger.info("[*] Re-enabling proxy")
        config.handler.add_proxys(olds)
    return res
