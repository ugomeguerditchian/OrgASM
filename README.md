
[![PyPI - Python](https://img.shields.io/badge/python-v3%2E8-181717?logo=python&style=flat)](https://github.com/ugomeguerditchian/ASMemble)

<h2 align="center">ASMemble</h2>

A tool for automated ASM (Attack Surface Monitoring)

## Features

- Obtaining results via [Alienvault](https://otx.alienvault.com/) and [Hackertarget](https://hackertarget.com/)
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
  python main.py -d <domain> -t <threads:Optional> -o <savefile:Bool>
```

> :memo: **Note:** help with `python main.py -h`

## Screenshots

![App Screenshot](./screenshots/Capture%20d%E2%80%99%C3%A9cran%202022-11-01%20095424.png)

![App Screenshot2](./screenshots/Capture%20d%E2%80%99%C3%A9cran%202022-11-01%20100931.png)

## Roadmap

- [ ] Service scanning amelioration
- [x] Args parse compatibility
- [ ] Selection of little, medium or big subdomains wordlist for bruteforcing test
- [ ] Recursive scan for subdomains bruteforcing
- [ ] Selection of others API websites like shodan, censys etc... (need to have an api key)
- [ ] Filtering real subdomains by access them (and detect potential redirections to others subdomains)
- [ ] Dorking test
- [ ] Export map options
- [ ] Possibility to add a list of already knows subdomains

## Authors

- [@ugomeguerditchian](https://github.com/ugomeguerditchian)

## Contributors

- [@MrStaf](https://github.com/MrStaf)
