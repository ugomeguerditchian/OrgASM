import json
import datetime
import lib.ip as ip_lib
import os
import random
import lib.custom_logger as custom_logger

logger = custom_logger.logger


class result:

    """
    Result class

    res.result = {
        "ip1": {
            "fqdns": {
                "domain1": {
                }
            },
    }

    res.deads = {
        "No ip": ["domain1"]
    }
    """

    def __init__(self):
        self.result = {}
        self.deads = {"No ip": []}
        self.metadata = {}

    def add_ip(self, ip: ip_lib.ip):
        """Add an ip to the result"""
        if ip not in self.result:
            self.result[ip] = {"fqdns": {}}

    def add_fqdn(self, ip: ip_lib.ip, fqdn: str):
        """Add a fqdn to the result"""
        if ip not in self.result:
            self.add_ip(ip)
        if fqdn not in self.result[ip]["fqdns"]:
            self.result[ip]["fqdns"][fqdn] = {}

    def check_if_fqdn_in_res(self, fqdn: str):
        """Check if a fqdn is in the result"""
        for ip in self.result:
            if fqdn in self.result[ip]["fqdns"]:
                return True
        return False

    def get_ip_in_res(self, ip: str):
        """Get the ip in the result"""
        for ip_ in self.result:
            if str(ip_.ip) == str(ip):
                return ip_
        return False

    def check_if_ip_in_res(self, ip: str):
        """Check if an ip is in the result"""
        for ip_ in self.result:
            if str(ip_.ip) == str(ip):
                return True
        return False

    def add_dead(self, fqdn: str, ip=None):
        """Add a dead fqdn to the result"""
        if ip:
            if ip not in self.deads:
                self.deads[ip] = [fqdn]
            else:
                self.deads[ip].append(fqdn)
        else:
            if fqdn not in self.deads["No ip"]:
                self.deads["No ip"].append(fqdn)

    def add_technology(self, ip: str, fqdn: str, technology: str, version: str):
        """Add a technology to the result"""
        if technology not in self.result[ip]["fqdns"][fqdn]["technologies"]:
            self.result[ip]["fqdns"][fqdn]["technologies"][technology] = version

    def add_port(self, ip: str, port: int, service: str, version: str, headers: dict):
        """Add a port to the result"""
        if port not in self.result[ip]["ports"]:
            self.result[ip]["ports"][port] = {
                "service": service,
                "version": version,
                "headers": headers,
            }

    def add_vuln(self, ip: str, vuln: dict):
        """Add a vuln to the result"""
        if vuln not in self.result[ip]["vulns"]:
            self.result[ip]["vulns"].append(vuln)

    def add_fqdn_vuln(self, ip: str, fqdn: str, vuln: dict):
        """Add a vuln to the result"""
        if vuln not in self.result[ip]["fqdns"][fqdn]["vulns"]:
            self.result[ip]["fqdns"][fqdn]["vulns"].append(vuln)

    def total_ips(self):
        """Return the total number of ips"""
        return len(self.result)

    def total_fqdns(self):
        """Return the total number of fqdns"""
        count = 0
        for ip in self.result:
            for fqdn in self.result[ip]["fqdns"]:
                count += 1
        return count

    def get_random_ip(self):
        """Return a random ip"""
        return random.choice(list(self.result.keys()))

    def get_random_fqdn(self):
        """Return a random fqdn"""
        ip = self.get_random_ip()
        return random.choice(list(self.result[ip]["fqdns"].keys()))

    def calculate_metadata(self):
        """Calculate the metadata"""
        self.metadata["total_ips"] = self.total_ips()
        self.metadata["total_fqdns"] = self.total_fqdns()

    def status(self):
        fqdns = 0
        for ip in self.result:
            for fqdn in self.result[ip]["fqdns"]:
                fqdns += 1
        ips = 0
        for ip in self.result:
            if str(ip.ip) != "Dead":
                ips += 1
        logger.info("Actual status: ")
        logger.info(f"IPs: {ips}, FQDNs: {fqdns}")
        count = 0
        for type in self.deads:
            for fqdn in self.deads[type]:
                count += 1
        logger.info(f"Dead FQDNs: {count}")

    def printer(self):
        """Print the result"""
        for ip in self.result:
            print(f"IP: {str(ip.ip)}")
            for fqdn in self.result[ip]["fqdns"]:
                print(f"\tFQDN: {fqdn}")
        print("Dead FQDNs: ")
        for type in self.deads:
            print(f"\t{type}")
            for fqdn in self.deads[type]:
                print(f"\t\t{fqdn}")

    def export(self, name: str):
        """Export the result to a json file"""
        # tranform all ip obj inside the res into str
        self.calculate_metadata()
        res_dict = {}
        for ip in self.result:
            res_dict[str(ip.ip)] = self.result[ip]
        # if exports folder doesn't exist, create it
        if not os.path.isdir("exports"):
            os.mkdir("exports")
        # if name folder doesn't exist, create it
        if not os.path.isdir(f"exports/{name}"):
            os.mkdir(f"exports/{name}")
        res_dict["metadata"] = self.metadata
        actual_date = datetime.datetime.now()
        with open(
            f"exports/{name}/{actual_date.strftime('%Y-%m-%d_%H-%M-%S')}.json", "w"
        ) as f:
            json.dump(res_dict, f, indent=4)
        logger.info(
            f"[*] Exported to exports/{name}/{actual_date.strftime('%Y-%m-%d_%H-%M-%S')}.json"
        )
