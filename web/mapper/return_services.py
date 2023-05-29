import lib.generics as gen
from lib.result import result


def main(prev_data: dict, result: result):
    """
    final = {
        "ip1": {"Services":[service1, service2, ...]},
        "ip2": {"Services":[service1, service2, ...]},
    """
    final = {}
    for ip in result.result:
        if str(ip.ip) in prev_data:
            final[str(ip.ip)] = prev_data[str(ip.ip)]
            final[str(ip.ip)]["Services"] = []
            for port in result.result[ip]["ports"]:
                final[str(ip.ip)]["Services"].append(
                    result.result[ip]["ports"][port]["service"]
                )
    return final
