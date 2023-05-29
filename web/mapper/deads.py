import lib.generics as gen
from lib.result import result


def main(result: result):
    final = []
    for ip in result.deads:
        for fqdn in result.deads[ip]:
            final.append(fqdn)
    return final
