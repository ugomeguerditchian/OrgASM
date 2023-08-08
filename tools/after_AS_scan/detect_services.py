from lib.ip import ip as ip_lib
from lib.result import result
import lib.generics as gen
import lib.custom_logger as custom_logger
from concurrent.futures import ThreadPoolExecutor

logger = custom_logger.logger


def main(config: gen.configuration, res: result):
    """
    This function detects services on each IP address in the result object
    and updates the result object with the detected services.

    :param config: the configuration object
    :param res: the result object
    :return: the updated result object
    """
    # Check if detect_services is enabled in the config file
    if not "detect_services" in config.config["TOOLS"]["after_AS_scan"]:
        logger.error("[*] Missing detect_services in TOOLS in config file")
        return res

    # Check if required parameters are present in the config file
    this_tool_config = config.config["TOOLS"]["after_AS_scan"]["detect_services"]
    to_have = ["workers", "activate"]
    for i in to_have:
        if i not in this_tool_config:
            logger.error(f"[*] Missing {i} in config file")
            return res

    # Check if detect_services is activated in the config file
    if not this_tool_config["activate"]:
        logger.info("[*] Skipping detect_services")
        return res

    logger.info("[*] Detecting services")

    # Disable proxy if it is enabled
    changed = False
    if not config.ip_trough_proxy and config.handler.there_is_proxy():
        logger.info("[*] Disabling proxy for services detection")
        olds = config.handler.remove_proxys()
        changed = True

    # Detect services on each IP address
    for ip in res.result:
        logger.info(f"[*] Detecting services on {ip.ip}")
        if ip.status:
            futures = []
            with ThreadPoolExecutor(
                max_workers=this_tool_config["workers"]
            ) as executor:
                # Detect services on each port in parallel
                for port in res.result[ip]["ports"]:
                    futures.append(executor.submit(ip.detect_service, port))
                for future in futures:
                    # Update the result object with the detected service
                    if future.result()["service"]:
                        res.result[ip]["ports"][future.result()["port"]][
                            "service"
                        ] = future.result()["service"]

    logger.info("[*] Detecting services finished")

    # Re-enable proxy if it was disabled
    if changed:
        logger.info("[*] Re-enabling proxy")
        config.handler.add_proxys(olds)

    return res
