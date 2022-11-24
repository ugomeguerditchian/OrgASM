
[![PyPI - Python](https://img.shields.io/badge/python-v3%2E8-181717?logo=python&style=flat)](https://github.com/ugomeguerditchian/OrgASM)

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

## Exports Exemple for the commands : python main.py -d python.org

```json

  {
      "151.101.120.223": {
          "subdomains": {
              "subdomain_withdomain": [
                  "www.python.org",
                  "peps.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "pypi.python.org",
                  "docs.python.org"
              ]
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "104.17.33.82": {
          "subdomains": {
              "subdomain_withdomain": [
                  "devguide.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
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
      },
      "184.105.176.47": {
          "subdomains": {
              "subdomain_withdomain": [
                  "discuss.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "46.4.94.207": {
          "subdomains": {
              "subdomain_withdomain": [
                  "hg.es.python.org",
                  "documentos-asociacion.es.python.org",
                  "calendario.es.python.org",
                  "openbadges.es.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "lists.es.python.org"
              ]
          },
          "ports": {
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
              "25955": "",
              "28443": "Unknown",
              "30416": "Unknown",
              "31588": "Unknown",
              "36641": "Unknown",
              "39499": "Unknown",
              "43490": "Unknown",
              "44650": "Unknown"
          }
      },
      "52.215.192.133": {
          "subdomains": {
              "subdomain_withdomain": [
                  "status.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "138.197.63.241": {
          "subdomains": {
              "subdomain_withdomain": [
                  "svn.python.org",
                  "console.python.org",
                  "legacy.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "python.org",
                  "jobs.python.org",
                  "planet.python.org",
                  "cheeseshop.python.org",
                  "packages.python.org"
              ]
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "185.199.111.153": {
          "subdomains": {
              "subdomain_withdomain": [
                  "es.python.org",
                  "comunidades.es.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "185.199.109.153": {
          "subdomains": {
              "subdomain_withdomain": [
                  "hacktoberfest.es.python.org",
                  "pycon-archive.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "www.es.python.org"
              ]
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "151.101.120.175": {
          "subdomains": {
              "subdomain_withdomain": [
                  "downloads.python.org",
                  "blog.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "doc.python.org",
                  "warehouse.python.org",
                  "testpypi.python.org"
              ]
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "161.35.181.181": {
          "subdomains": {
              "subdomain_withdomain": [
                  "wiki.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "buildbot.python.org"
              ]
          },
          "ports": {
              "22": "ssh",
              "80": "http",
              "443": "https",
              "9020": "tambora",
              "20000": "dnp",
              "20003": "commtact-https",
              "20004": "Unknown",
              "20005": "openwebnet",
              "20006": "Unknown",
              "20010": "Unknown",
              "20100": "Unknown"
          }
      },
      "34.201.80.84": {
          "subdomains": {
              "subdomain_withdomain": [
                  "staging.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "23.22.5.68": {
          "subdomains": {
              "subdomain_withdomain": [
                  "education.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "3.10.218.93": {
          "subdomains": {
              "subdomain_withdomain": [
                  "chat.uk.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "54.227.157.72": {
          "subdomains": {
              "subdomain_withdomain": [
                  "africa.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "159.203.120.55": {
          "subdomains": {
              "subdomain_withdomain": [
                  "speed.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "22": "ssh",
              "80": "http",
              "443": "https",
              "9020": "tambora",
              "20000": "dnp",
              "20003": "commtact-https",
              "20004": "Unknown",
              "20005": "openwebnet",
              "20006": "Unknown",
              "20010": "Unknown",
              "20100": "Unknown"
          }
      },
      "52.56.203.177": {
          "subdomains": {
              "subdomain_withdomain": [
                  "membership.uk.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "22": "ssh",
              "80": "http",
              "443": "https",
              "2222": "EtherNet/IP-1",
              "4455": "prchat-user",
              "4456": "prchat-server"
          }
      },
      "104.198.14.52": {
          "subdomains": {
              "subdomain_withdomain": [
                  "uk.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "51.15.237.199": {
          "subdomains": {
              "subdomain_withdomain": [
                  "comunidad.es.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "22": "ssh",
              "80": "http",
              "443": "https"
          }
      },
      "185.199.108.153": {
          "subdomains": {
              "subdomain_withdomain": [
                  "community.uk.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "134.209.40.52": {
          "subdomains": {
              "subdomain_withdomain": [
                  "planetpython.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "22": "ssh",
              "80": "http",
              "443": "https"
          }
      },
      "188.166.48.69": {
          "subdomains": {
              "subdomain_withdomain": [
                  "bugs.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "22": "ssh",
              "80": "http",
              "443": "https",
              "465": "submissions",
              "587": "submission"
          }
      },
      "142.250.179.83": {
          "subdomains": {
              "subdomain_withdomain": [
                  "blog-ko.python.org",
                  "blog-ja.python.org",
                  "blog-pt.python.org",
                  "blog-de.python.org",
                  "blog-es.python.org",
                  "blog-ru.python.org",
                  "blog-tw.python.org",
                  "blog-fr.python.org",
                  "blog-ro.python.org",
                  "blog-cn.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https"
          }
      },
      "140.211.10.69": {
          "subdomains": {
              "subdomain_withdomain": [
                  "front.python.org"
              ],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": []
          },
          "ports": {
              "80": "http",
              "443": "https",
              "6443": "sun-sr-https"
          }
      },
      "151.101.128.223": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "pypi.org"
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "151.101.121.63": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "test.pypi.org"
              ],
              "subdomain_with_redirect": []
          },
          "ports": {}
      },
      "151.101.65.63": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [
                  "pythonhosted.org"
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
      "104.17.32.82": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "packaging.python.org"
              ]
          },
          "ports": {}
      },
      "188.166.95.178": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "mail.python.org"
              ]
          },
          "ports": {}
      },
      "163.172.190.132": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "socios.es.python.org"
              ]
          },
          "ports": {}
      },
      "138.197.54.234": {
          "subdomains": {
              "subdomain_withdomain": [],
              "subdomain_withoutdomain": [],
              "subdomain_with_redirect": [
                  "hg.python.org"
              ]
          },
          "ports": {}
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
