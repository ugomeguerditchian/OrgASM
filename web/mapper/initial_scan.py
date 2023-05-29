import lib.generics as gen
from lib.result import result


def main(result: result):
    """
    final = {
        "ip1": {FQDNs:[fqdn1, fqdn2, ...]},
        "ip2": {FQDNs:[fqdn1, fqdn2, ...]},
    """
    final = {}
    for ip in result.result:
        final[str(ip.ip)] = {"FQDNs": []}
        for fqdn in result.result[ip]["fqdns"]:
            final[str(ip.ip)]["FQDNs"].append(fqdn)
    return final
