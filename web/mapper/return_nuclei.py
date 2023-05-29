import lib.generics as gen
from lib.result import result


def main(result: result):
    """
    <th>Name</th>
    <th>Severity</th>
    <th>Cve-id</th>
    <th>Cwe-id</th>
    <th>Cvss-metrics</th>
    <th>Cvss-score</th>
    <th>Description</th>
    <th>Reference</th>
    <th>Type</th>
    <th>Host</th>
    <th>Matched-at</th>
    <th>Extracted-results</th>
    <th>Ip</th>
    <th>Timestamp</th>
    <th>curl-command</th>
    <th>matcher-status</th>
    <th>matched-line</th>
    <th>matcher-name</th>
    <th>Info | tags</th>
    <th>Info | Metadata | verified</th>
    <th>Info | Metadata | fofa-query</th>
    <th>Info | Metadata | shodan-query</th>
    <th>template</th>
    <th>template-url</th>
    <th>template-id</th>
    <th>template-path</th>
    <th>Info | author</th>>
    final = {
        "ip1": {[{Name:[name], Severity:[severity]...}, {Name:[name], Severity:[severity]...}, ...]}
        "ip2": {[{Name:[name], Severity:[severity]...}, {Name:[name], Severity:[severity]...}, ...]}
        "fqdn": {[{Name:[name], Severity:[severity]...}, {Name:[name], Severity:[severity]...}, ...]}
    """
    final = {}
    for ip in result.result:
        if "vulns" in result.result[ip]:
            final[str(ip.ip)] = []
            for vuln in result.result[ip]["vulns"]:
                if "info" in vuln:
                    infos = vuln.pop("info")
                    for info in infos:
                        vuln[info] = infos[info]
                final[str(ip.ip)].append(vuln)
        for fqdn in result.result[ip]["fqdns"]:
            if "vulns" in result.result[ip]["fqdns"][fqdn]:
                final[fqdn] = []
                for vuln in result.result[ip]["fqdns"][fqdn]["vulns"]:
                    if "info" in vuln:
                        infos = vuln.pop("info")
                        for info in infos:
                            vuln[info] = infos[info]
                    final[fqdn].append(vuln)
    return final
