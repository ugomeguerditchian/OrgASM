import lib.custom_logger as custom_logger
import lib.generics as gen
from lib.handler import handler
import json

logger = custom_logger.logger


def main(domain, handler: handler, key: str):
    # get all the subdomain of the domain from hackertarget
    # the url is https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names
    """
    example :
        {
                "id":"5115677540",
                "tbs_sha256":"6278c2fea922f62ad1c1ed48ade07672b09f51028a54da7fa33948cfbf11675b",
                "cert_sha256":"1cbee6d40f4a646a5617542f4c30a9266da16420451b24d9e76e496113373159",
                "dns_names":["fage.fr","jean-marie.fage.fr","www.fage.fr"],
                "pubkey_sha256":"ace330c79269aa0ce625bd9350ecab83494f3072776ffebc6c09bc2a0834b4b1",
                "not_before":"2023-04-20T12:29:40Z",
                "not_after":"2023-07-19T12:29:39Z",
                "revoked":false
        },
        {
                "id":"5128915982",
                "tbs_sha256":"71c29dbcd7b1b31426f6a196d16c15c7b420972fd3f9f6facc8bee51a9c1be37",
                "cert_sha256":"b7bda7b1d36eb4c381b75382c516e7b90552ebd60fbaeac754b2690c60137198",
                "dns_names":["res01.benoit.fage.fr"],
                "pubkey_sha256":"262ade2072ab5a753b3ac946015e9a4102b0a3f5126dd1e0e6951fadcfc9e0db",
                "not_before":"2023-04-23T16:17:16Z",
                "not_after":"2023-07-22T16:17:15Z",
                "revoked":false
        },
    """
    subdomains = []
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    response = handler.get(url, until_ok=True)._body.decode("utf-8")
    response = json.loads(response)
    for i in response:
        if "dns_names" not in i:
            continue
        for sub in i["dns_names"]:
            if not sub in subdomains and not "*" in sub and "." in sub:
                subdomains.append(sub)
    return subdomains
