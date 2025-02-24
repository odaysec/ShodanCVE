# ShodanCVE
CVE Hunter is an automated reconnaissance tool designed for bug hunters, leveraging Shodan's InternetDB and CVEDB APIs

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge" />
  <img src="https://img.shields.io/github/license/odaysec/ShodanCVE?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge" />
  <br>
  <img src="https://img.shields.io/github/stars/odaysec/ShodanCVE?style=for-the-badge" />
  <img src="https://img.shields.io/github/issues/odaysec/ShodanCVE?style=for-the-badge" />
  <br>
  <img src="https://img.shields.io/badge/Made_in-odaysec-orange?style=for-the-badge" />
</p>

ShodanCVE is an automated reconnaissance tool designed for bug hunters, leveraging Shodan's InternetDB and CVEDB APIs. It retrieves open ports, hostnames, tags, and vulnerabilities for a given IP and fetches CVE details, including affected products and CVSS scores. Results are color-coded by severity for easy analysis.

## Features
- Fetch open ports, hostnames, and associated vulnerabilities for an IP address.
- Retrieve CVE details including severity levels.
- Color-coded output for easy identification of risk levels.
- Support for file input (`-f`) and output saving (`-o`).
- Option to display combined CVEs and open ports.

<h2 align="center">Tutorial ShodanCVE</h2>

[![asciicast](https://asciinema.org/a/705165.svg)](https://asciinema.org/a/705165)

## Installation
```bash
# Clone the repository
git clone https://github.com/odaysec/ShodanCVE.git
cd ShodanCVE

# Install required dependencies
pip install -r requirements.txt

# Run the tool
python shodancve.py --help
```

## Command Usage
### Display Help Menu
```bash
python ShodanCVE.py -h
```

### Scan a Single IP
```bash
python ShodanCVE.py --ip 192.20.1.1
```

### Scan a List of IPs from a File
```bash
python ShodanCVE.py -f targets.txt
```

### Display CVEs Only
```bash
python ShodanCVE.py --ip 192.20.1.1 --cves
```


### Display Open Ports Only
```bash
python ShodanCVE.py --ip 192.20.1.1 --ports
```

### Display Hostnames Only
```bash
python ShodanCVE.py --ip 192.20.1.1 --host
```

### Show CVEs with Ports
```bash
python ShodanCVE.py --ip 192.20.1.1 --cve+ports
```

### Show All Results (Default Behavior)
```bash
python ShodanCVE.py --ip 192.20.1.1
```

## Attribution
This tool uses data from the [Shodan InternetDB](https://internetdb.shodan.io/) and [CVE Database](https://cvedb.shodan.io/). Credits to Shodan for their valuable security intelligence.

## Disclaimer
ShodanCVE is intended for educational and authorized security research purposes only. Unauthorized usage against systems without explicit permission is illegal.

## License
ShodanCVE is released under the MIT License. See `LICENSE` for more details.
