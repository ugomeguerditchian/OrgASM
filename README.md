
[![PyPI - Python](https://img.shields.io/badge/python-v3%2E8-181717?logo=python&style=flat)](https://github.com/ugomeguerditchian/OrgASM)

<h2 align="center">OrgASM</h2>

A tool for Organized ASM (Attack Surface Monitoring).

OrgASM can detect subdomains, detect all ip related to them, scan all open ports and detect services.

With the power of multi-threading it can be as fast as you want (and has you can) 🚀

In the very next future it will be shodan and censys friendly 🙌

We will also soon released the dorking compatibility and web parser 🥸

## Features

- Obtaining results via [Alienvault](https://otx.alienvault.com/), [Hackertarget](https://hackertarget.com/) and [crt.sh](https://crt.sh/)
- Subdomain Bruteforcing
- DNS query
- IP Sorting and scanning (Ports and services)
- JSON Export

## Installation

Install **OrgASM** with pip
(:warning: *Python 3.8 >= Needed*)

```bash
  git clone https://github.com/ugomeguerditchian/OrgASM
  cd OrgASM
  pip install -r requirements.txt
  usage: main.py [-h] [-d DOMAIN] [-w WORDLIST] [-wT WORDLISTTHREADS] [-dT DNSTHREADS] [-iS IPSCANTYPE]
                [-iT IPTHREADS] [-sT SUBDOMAINSTHREADS] [-o]

  options:
    -h, --help            show this help message and exit
    -d DOMAIN, --domain DOMAIN
                          Domain to scan
    -w WORDLIST, --wordlist WORDLIST
                          Wordlist to use (small, medium(default), big)
    -wT WORDLISTTHREADS, --wordlistThreads WORDLISTTHREADS
                          Number of threads to use for Wordlist(default 500)
    -dT DNSTHREADS, --dnsThreads DNSTHREADS
                          Number of threads to use for DNS query(default 500)
    -iS IPSCANTYPE, --IPScanType IPSCANTYPE
                          Choose what IPs to scan (W: only subdomains IP containing domain given, WR: only
                          subdomains IP containtaining domain given but with a redirect, A: All subdomains
                          detected
    -iT IPTHREADS, --IPthreads IPTHREADS
                          Number of threads to use for IP scan(default 2000)
    -sT SUBDOMAINSTHREADS, --subdomainsThreads SUBDOMAINSTHREADS
                          Number of threads to use for check real subdomains(default 500)
    -o, --output          If provided > save the results, default is False
```

> :memo: **Note:** help with `python main.py -h`

## Exports Exemple for the commands : python main.py -d exemple.com

```json

  {
      "34.102.136.180": {
          "subdomains": {
              "subdomain_withdomain": [
                  "exemple.com",
                  "www.exemple.com"
              ],
              "subdomain_withoutdomain": [
                  "www.loimaylanh.vn"
              ],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "66.81.199.53": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "fwdservice.com"
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "198.49.23.145": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "www.appgroup.ca"
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "192.203.230.10": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "e.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "193.0.14.129": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "k.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "192.33.4.12": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "c.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "199.9.14.201": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "b.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "198.97.190.53": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "h.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "192.112.36.4": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "g.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "192.58.128.30": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "j.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "199.7.91.13": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "d.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "198.41.0.4": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "a.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "192.36.148.17": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "i.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "192.5.5.241": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "f.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "202.12.27.33": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "m.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "199.7.83.42": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "l.root-servers.net."
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "208.73.211.70": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "208.73.211.70"
              ]
          },
          "ports": {}
      },
      "198.185.159.144": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "appgroup.ca"
              ]
          },
          "ports": {}
      }
  }

```

## Roadmap

- [ ] Service scanning amelioration
- [ ] Add DNS transfer zone test
- [ ] Recursive scan for subdomains bruteforcing
- [ ] Selection of others API websites like shodan, censys etc... (need to have an api key)
- [X] Filtering real subdomains by access them (and detect potential redirections to others subdomains)
- [ ] Dorking test
- [ ] Export map options
- [ ] Possibility to add a list of already knows subdomains
- [ ] Choice for doing only API scan, Bruteforce scan or IP scan (or all)
- [ ] Config file (yaml)
- [X] Choice for doing IP scan only on target associated with main domain
- [ ] Add vulnerability scan
## Authors

- [@ugomeguerditchian](https://github.com/ugomeguerditchian)

## Contributors

- [@MrStaf](https://github.com/MrStaf)
