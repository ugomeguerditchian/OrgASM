import lib.generics as gen
from lib.result import result


def main(result: result):
    """
    final = {
        "ip1": {Ports:[port1, port2, ...]},
        "ip2": {Ports:[port1, port2, ...]},
    """
    final = {}
    for ip in result.result:
        final[str(ip.ip)] = {"Ports": []}
        for port in result.result[ip]["ports"]:
            final[str(ip.ip)]["Ports"].append(port)
    return final
