# 🛡️ Compromised Website Scanner 🕵️‍♂️
Compromised Website Scanner is an advanced security tool designed to scan websites for malicious content, vulnerabilities, and suspicious activity. It checks the site itself as well as any external JavaScript resources it links to, ensuring comprehensive coverage.

## DISCLAIMER:

`This Project is a work in progress and currently untested - Check back for updates!`

## 🔍 Key Features:

* Scans website content and JavaScript links for malicious code 🧑‍💻
* Checks URLs against Google Safe Browsing & Abuse.ch for threat intelligence 🌐
* Detects suspicious redirects and misconfigured HTTP headers 🔄
* Identifies CMS and cross-references against the CVE database 💻
* Provides an option to display results or save them to CSV 📊

## Requirements

* [Abuse.ch API Key](https://urlhaus-api.abuse.ch/)
* [Google Safe Browsing API Key](https://developers.google.com/safe-browsing/v4)

## Usage

> Scan webpage and display to the screen

```bash
python scanner.py http://example.com
```

> Scan webpage and output to CSV

```bash
python scanner.py http://example.com --csv
```
