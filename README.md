[![PyPI - Python](https://img.shields.io/badge/python-v3%2E8-181717?logo=python&style=for-the-badge)](https://github.com/ugomeguerditchian/OrgASM)
![Lines of code](https://img.shields.io/tokei/lines/github.com/ugomeguerditchian/OrgASM?style=for-the-badge)

<h2 align="center">OrgASM</h2>

A tool for Organized ASM (Attack Surface Monitoring).

OrgASM can detect subdomains, detect all ip related to them, scan all open ports and detect services.

With the power of multi-threading it can be as fast as you want (and has you can) 🚀

In the very next future it will be shodan and censys friendly 🙌

We will also soon released the dorking compatibility and web parser 🥸

## Features

- Obtaining results via [Alienvault](https://otx.alienvault.com/), [Hackertarget](https://hackertarget.com/) and [crt.sh](https://crt.sh/)
- Possibility to add a list of already knows subdomains
- Subdomain Bruteforcing
- Recursive scan
- DNS query
- IP Sorting and scanning (Ports and services)
- JSON Export
- Filtering real subdomains by access them (and detect potential redirections to others subdomains).
- You can choose if you want only OSINT mode (API request on third party websites), Bruteforce and IPs scanning

## Installation

Install **OrgASM** with pip
(:warning: *Python 3.8 >= Needed*)

```bash
  git clone https://github.com/ugomeguerditchian/OrgASM
  cd OrgASM
  pip install -r requirements.txt
    usage: main.py [-h] [-d DOMAIN] [-sF SUBFILE] [-w WORDLIST] [-wT WORDLISTTHREADS] [-dT DNSTHREADS] [-iS IPSCANTYPE] [-iT IPTHREADS]
                [-sT SUBDOMAINSTHREADS] [-o]

    options:
    -h, --help            show this help message and exit
    -d DOMAIN, --domain DOMAIN
                            Domain to scan
    -m MODE, --mode MODE  Mode to use, O for OSINT (API request), B for bruteforce, S for IP scan (default OBS)
    -sF SUBFILE, --subfile SUBFILE
                            Path to file with subdomains, one per line
    -R RECURSIVE, --recursive RECURSIVE
                            Recursive scan, will rescan all the subdomains finds and go deeper as you want, default is 0
    -w WORDLIST, --wordlist WORDLIST
                            Wordlist to use (small, medium(default), big)
    -wT WORDLISTTHREADS, --wordlistThreads WORDLISTTHREADS
                            Number of threads to use for Wordlist(default 500)
    -dT DNSTHREADS, --dnsThreads DNSTHREADS
                            Number of threads to use for DNS query(default 500)
    -iS IPSCANTYPE, --IPScanType IPSCANTYPE
                            Choose what IPs to scan (W: only subdomains IP containing domain given, WR: only subdomains IP containtaining domain given but with a redirect, A: All subdomains detected
    -iT IPTHREADS, --IPthreads IPTHREADS
                            Number of threads to use for IP scan(default 2000)
    -sT SUBDOMAINSTHREADS, --subdomainsThreads SUBDOMAINSTHREADS
                            Number of threads to use for check real subdomains(default 500)
    -o, --output          If provided > save the results, default is False
```

> :memo: **Note:** help with `python main.py -h`

## Exports Exemple for the commands : python main.py -d example.com

```json

  {
      "1.2.3.4" {
        "subdomains" {
          "subdomains_withdomain":["example.com", "www.example.com", "admin.example.com"],
          "subdomains_withoutdomain":["gitlab.azer.com"],
          "subdomains_with_redirect":["dashboard.example.com"]
        },
        "ports" : {
          "22": "ssh",
          "53": "domain",
          "80": "http",
          "443": "https",
          "465": "submissions",
          "587": "submission",
          "993": "imaps",
          "2222": "EtherNet/IP-1",
          "8088": "radan-http",
          "14938": "Unknown",
          "16761": "Unknown",
          "23878": "Unknown",
          "24272": "Unknown",
          "24304": "Unknown",
          "24478": "Unknown",
          "25955": "Unknown",
          "28443": "Unknown",
          "30416": "Unknown",
          "31588": "Unknown",
          "36641": "Unknown",
          "39499": "Unknown",
          "43490": "Unknown",
          "44650": "Unknown"
        }
      },
      "2.3.4.5" {
        "subdomains" {
          "subdomains_withdomain":["dev.example.com", "pre-prod.example.com"],
          "subdomains_withoutdomain":[],
          "subdomains_with_redirect":["prod.example.com"]
          },
        "ports": {
          "80": "http",
          "443": "https",
          "2052": "clearvisn",
          "2053": "knetd",
          "2082": "infowave",
          "2083": "radsec",
          "2086": "gnunet",
          "2087": "eli",
          "2095": "nbx-ser",
          "2096": "nbx-dir",
          "8080": "http-alt",
          "8443": "pcsync-https",
          "8880": "cddbp-alt"
        }
      }
  }

```

## Roadmap

- [ ] Service scanning amelioration
- [ ] Add DNS transfer zone test
- [X] Recursive scan for subdomains bruteforcing
- [ ] Selection of others API websites like shodan, censys etc... (need to have an api key)
- [X] Filtering real subdomains by access them (and detect potential redirections to others subdomains)
- [ ] Dorking test
- [ ] Export map options
- [X] Possibility to add a list of already knows subdomains
- [X] Choice for doing only API scan, Bruteforce scan or IP scan (or all)
- [ ] Config file (yaml)
- [X] Choice for doing IP scan only on target associated with main domain
- [ ] Add vulnerability scan
## Authors

- [@ugomeguerditchian](https://github.com/ugomeguerditchian)

## Contributors

- [@MrStaf](https://github.com/MrStaf)
