import lib.generics as gen
from lib.result import result


def main(result: result):
    """
    final = {
        "http://example.com": {"IP":"192.168.1.1", "Technologie":[tech1, tech2, ...], "Version": [version], "Headers":[header1, header2, ...]},
        "https://1.1.1.1:80": {"IP":"192.168.1.1", "Technologie":[tech1, tech2, ...], "Version": [version], "Headers":[header1, header2, ...]},
    """
    final = {}
    for ip in result.result:
        for fqdn in result.result[ip]["fqdns"]:
            final[fqdn] = {
                "IP": [str(ip.ip)],
                "Technologies": [],
                "Version": [],
                "Headers": [],
            }
            if "technologies" in result.result[ip]["fqdns"][fqdn]:
                for tech in result.result[ip]["fqdns"][fqdn]["technologies"]["tech"]:
                    if tech not in final[fqdn]["Technologies"]:
                        final[fqdn]["Technologies"].append(tech["name"])
                        final[fqdn]["Version"].append(tech["version"])
                for header in result.result[ip]["fqdns"][fqdn]["technologies"][
                    "headers"
                ]:
                    if header not in final[fqdn]["Headers"]:
                        final[fqdn]["Headers"].append(header)
        for port in result.result[ip]["ports"]:
            if "technologies" in result.result[ip]["ports"][port]:
                final[str(ip.ip) + ":" + str(port)] = {
                    "IP": [str(ip.ip)],
                    "Technologies": [],
                    "Version": [],
                    "Headers": [],
                }
                if "technologies" in result.result[ip]["ports"][port]:
                    for tech in result.result[ip]["ports"][port]["technologies"][
                        "tech"
                    ]:
                        if (
                            tech
                            not in final[str(ip.ip) + ":" + str(port)]["Technologies"]
                        ):
                            final[str(ip.ip) + ":" + str(port)]["Technologies"].append(
                                tech["name"]
                            )
                            final[str(ip.ip) + ":" + str(port)]["Version"].append(
                                tech["version"]
                            )
                    for header in result.result[ip]["ports"][port]["technologies"][
                        "headers"
                    ]:
                        if header not in final[str(ip.ip) + ":" + str(port)]["Headers"]:
                            final[str(ip.ip) + ":" + str(port)]["Headers"].append(
                                header
                            )

    return final
