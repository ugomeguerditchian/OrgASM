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
- IP Sorting and scanning (Ports and services)
- OrgASM can detect services using Wappalyzer sources ! Thanks to [webtech](https://github.com/ShielderSec/webtech)
- Harvesting of headers
- Filtering real subdomains by access them (and detect potential redirections to others subdomains).
- You can choose if you want only OSINT mode (API request on third party websites), Bruteforce and IPs scanning
- JSON Export

## Installation

Install **OrgASM** with pip
(:warning: *Python 3.8 >= Needed*)

```
  git clone https://github.com/ugomeguerditchian/OrgASM
  cd OrgASM
  pip install -r requirements.txt
  usage: main.py [-h] [-d DOMAIN] [-m MODE] [-sF SUBFILE] [-R RECURSIVE] [-w WORDLIST] [-wT WORDLISTTHREADS] [-iS IPSCANTYPE] [-iT IPTHREADS] [-sT SUBDOMAINSTHREADS] [-cP CHECKPORTSTHREADS] [-dT DETECTTECHNO] [-o]

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
    -iS IPSCANTYPE, --IPScanType IPSCANTYPE
                          Choose what IPs to scan (W: only subdomains IP containing domain given, WR: only subdomains IP containtaining domain given but with a redirect, A: All subdomains detected
    -iT IPTHREADS, --IPthreads IPTHREADS
                          Number of threads to use for IP scan(default 2000)
    -sT SUBDOMAINSTHREADS, --subdomainsThreads SUBDOMAINSTHREADS
                          Number of threads to use for check real subdomains(default 500)
    -cP CHECKPORTSTHREADS, --checkPortsThreads CHECKPORTSTHREADS
                          Check all ports of subdomains for all IP in IPScantype (-iS) and try to access them to check if it's a webport (default True) (deactivate with 0)
    -dT DETECTTECHNO, --detectTechno DETECTTECHNO
                          Detect techno used by subdomains (default True) (deactivate with False)
    -o, --output          If provided > save the results, default is False
```

> :memo: **Note:** help with `python main.py -h`

## Exports Exemple for the commands : python main.py -d example.com

```json

  {
      "1.2.3.4" {
        "subdomains" {
          "subdomains_withdomain":[
            "example.com", 
            "www.example.com", 
            "admin.example.com"
            ],
          "subdomains_withoutdomain":[
            "gitlab.azer.com"
            ],
          "subdomains_with_redirect":[
            "dashboard.example.com"
            ]
        },
      "web_techno" :{
        "example.com":{
          "tech":[
            {
              "name": "Apache HTTP Server",
              "version": null
            }
            {
              "name": "Boostrap",
              "version": "3.3.7"
            }
          ],
          "headers":[
              {
                  "name": "Access-Control-Allow-Credentials",
                  "value": "true"
              },
              {
                  "name": "Access-Control-Expose-Headers",
                  "value": "Content-Range"
              },
              {
                  "name": "X-Served-By",
                  "value": "content.example.com"
              }
          ]
        }
      }
      "ports": {
    "21": "ftp",
    "53": "domain",
    "80": {
        "tech": [
            {
                "name": "Apache HTTP Server",
                "version": null
            }
        ],
        "headers": []
    },
    "110": "pop3",
    "111": "sunrpc",
    "143": "imap",
    "443": {
        "tech": [
            {
                "name": "WordPress",
                "version": "6.0.3"
            },
            {
                "name": "PHP",
                "version": "7.4.32"
            },
            {
                "name": "PHP",
                "version": null
            },
            {
                "name": "WordPress",
                "version": null
            },
            {
                "name": "Apache HTTP Server",
                "version": null
            }
        ],
        "headers": []
    },
    "465": "submissions",
    "587": "submission",
    "993": "imaps",
    "995": "pop3s",
    "1407": "tibet-server",
    "2077": "tsrmagt",
    "2078": "tpcsrvr",
    "2079": "idware-router",
    "2080": "autodesk-nlm",
    "2082": {
        "tech": [
            {
                "name": "cPanel",
                "version": null
            }
        ],
        "headers": []
    },
      },
      "2.3.4.5" {
        "subdomains" {
          "subdomains_withdomain":[
            "dev.example.com", 
            "pre-prod.example.com"
            ],
          "subdomains_withoutdomain":[],
          "subdomains_with_redirect":[
            "prod.example.com"
            ]
          },
        "web_techno":{
          "dev.example.com": {
            "tech" : [
              {
                "name": "Apache HTTP Server",
                "version": null
              }
            ],
            "headers": []
          },
          "pre-prod.example.com": {
            "tech" : [
              {
                "name": "Next.js",
                "version": null
              }
            ],
            "headers": []
          },
          }
        }
        "ports": {
            "80": {
                "tech": [
                    {
                        "name": "Bootstrap",
                        "version": "3.3.7"
                    },
                    {
                        "name": "OpenResty",
                        "version": null
                    }
                ],
                "headers": []
            },
            "81": {
                "tech": [
                    {
                        "name": "OpenResty",
                        "version": null
                    }
                ],
                "headers": []
            },
            "443": "https",
            "2020": "xinupageserver",
            "3000": {
                "tech": [
                    {
                        "name": "Next.js",
                        "version": null
                    }
                ],
                "headers": []
            },
            "3003": {
                "tech": [
                    {
                        "name": "Next.js",
                        "version": null
                    }
                ],
                "headers": [
                    {
                        "name": "x-nextjs-cache",
                        "value": "STALE"
                    }
                ]
            },
            "8055": {
                "tech": [
                    {
                        "name": "Directus",
                        "version": null
                    }
                ],
                "headers": [
                    {
                        "name": "Access-Control-Allow-Credentials",
                        "value": "true"
                    },
                    {
                        "name": "Access-Control-Expose-Headers",
                        "value": "Content-Range"
                    }
                ]
            },
            "8080": {
                "tech": [],
                "headers": [
                    {
                        "name": "Server-Timing",
                        "value": "total;dur=12.833, render;dur=5.594"
                    },
                    {
                        "name": "X-Download-Options",
                        "value": "noopen"
                    },
                    {
                        "name": "X-Robots-Tag",
                        "value": "noindex, nofollow"
                    }
                ]
            }
        }
      }
  }

```

## Roadmap

- [X] Service scanning amelioration
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
