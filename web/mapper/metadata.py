import lib.generics as gen
from lib.result import result


def main(result: result):
    """ """
    input_given = result.metadata["input"]
    input_type = result.metadata["input_type"]
    date = result.metadata["date"]
    total_time = result.metadata["time"]
    total_ips = result.total_ips()
    total_fqdns = result.total_fqdns()

    return [
        f"Input Given : {input_given}",
        f"Input Type : {input_type}",
        f"Date : {date}",
        f"Total Time : {total_time}",
        f"Total IPs : {total_ips}",
        f"Total FQDNs : {total_fqdns}",
    ]
