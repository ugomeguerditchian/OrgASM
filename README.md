
[![PyPI - Python](https://img.shields.io/badge/python-v3%2E8-181717?logo=python&style=flat)](https://github.com/ugomeguerditchian/ASMemble)

<h2 align="center">ASMemble</h2>

A tool for automated ASM (Attack Surface Monitoring).

ASMemble can detect subdomains, detect all ip related to them, scan all open ports and detect services.

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

Install **ASMemble** with pip
(:warning: *Python 3.8 >= Needed*)

```bash
  git clone https://github.com/ugomeguerditchian/ASMemble
  cd ASMemble
  pip install -r requirements.txt
  usage: main.py [-h] [-d DOMAIN] [-w WORDLIST] [-wT WORDLISTTHREADS] [-iT IPTHREADS] [-o {True,False}]

  options:
    -h, --help            show this help message and exit
    -d DOMAIN, --domain DOMAIN
                          Domain to scan
    -w WORDLIST, --wordlist WORDLIST
                          Wordlist to use (small, medium(default), big)
    -wT WORDLISTTHREADS, --wordlistThreads WORDLISTTHREADS
                          Number of threads to use for Wordlist(default 500)
    -iT IPTHREADS, --IPthreads IPTHREADS
                          Number of threads to use for IP Scanning(default 2000)
    -o {True,False}, --output {True,False}
                          Output save, default is False
```

> :memo: **Note:** help with `python main.py -h`

## Screenshots

![App Screenshot](./screenshots/Capture%20d%E2%80%99%C3%A9cran%202022-11-01%20095424.png)

![App Screenshot2](./screenshots/Capture%20d%E2%80%99%C3%A9cran%202022-11-01%20100931.png)

## Roadmap

- [ ] Service scanning amelioration
- [ ] Add DNS transfer zone test
- [ ] Recursive scan for subdomains bruteforcing
- [ ] Selection of others API websites like shodan, censys etc... (need to have an api key)
- [ ] Filtering real subdomains by access them (and detect potential redirections to others subdomains)
- [ ] Dorking test
- [ ] Export map options
- [ ] Possibility to add a list of already knows subdomains
- [ ] Choice for doing only API scan, Bruteforce scan or IP scan (or all)
- [ ] Config file (yaml)
- [ ] Choice for doing IP scan only on target associated with main domain
- [ ] Add vulnerability scan
## Authors

- [@ugomeguerditchian](https://github.com/ugomeguerditchian)

## Contributors

- [@MrStaf](https://github.com/MrStaf)
