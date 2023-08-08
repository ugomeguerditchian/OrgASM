from lib.ip import ip as ip_lib
from lib.result import result
import lib.generics as gen
import lib.custom_logger as custom_logger

logger = custom_logger.logger


def main(config: gen.configuration, res: result):
    """
    This function is the main function that scans the ports for each IP address in the result object.
    :param config: gen.configuration object that contains the configuration information.
    :param res: result object that contains the IP addresses to scan.
    :return: result object with the ports scanned for each IP address.
    """
    # Check if ports_scanner is in the config file
    if not "ports_scanner" in config.config["TOOLS"]["after_AS_scan"]:
        logger.error("[*] Missing ports_scanner in TOOLS in config file")
        return

    # Check if workers and activate are in the ports_scanner configuration
    this_tool_config = config.config["TOOLS"]["after_AS_scan"]["ports_scanner"]
    to_have = ["workers", "activate"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return

    # Check if ports_scanner is activated in the config file
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping ports_scanner")
        return

    # Disable proxy if it is enabled
    changed = False
    if not config.ip_trough_proxy and config.handler.there_is_proxy():
        logger.info("[*] Disabling proxy for ports scan")
        olds = config.handler.remove_proxys()
        changed = True

    # Scan ports for each IP address in the result object
    logger.info("[*] Scanning ports")
    ports_range = range(1, 65535)
    for ip in res.result:
        logger.info(f"[*] Scanning ports for {ip.ip}")
        ip.ping()
        if ip.status:
            ip.ports_scan(ports_range, this_tool_config["workers"])
            res.result[ip]["ports"] = ip.ports
        else:
            logger.info(
                f"[*] Skipping port scan for {ip.ip} because it is not reachable"
            )

    logger.info("[*] Port scan finished")

    # Re-enable proxy if it was disabled
    if changed:
        logger.info("[*] Re-enabling proxy")
        config.handler.add_proxys(olds)

    return res
