# CVE Fetcher Tool

A Python script to fetch and filter CVEs (Common Vulnerabilities and Exposures) from the [National Vulnerability Database](https://nvd.nist.gov/).

[Data source](https://nvd.nist.gov/developers/data-sources)

This tool uses the [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)

# Features
- Fetches data of CVE's :
    ✅ CVE ID
  
    ✅ Description (English version only)
  
    ✅ Exploitability score
  
    ✅ Colour coded base severity (LOW, MEDIUM, HIGH)
  
    ✅ Affected products (CPEs)
  

- Filter results by:
  
    ✅ CVE ID (`--cve-id`)
  
    ✅ Keywords in description (`--keyword`)
  
    ✅ Severity level (`--severity`: LOW, MEDIUM, HIGH)
  
    ✅ Publication dates (`--since` and `--until`)
  

- Flexible output:
  
    ✅ defaults to 5CVEs per request without (`--limit`)

- Option to save results in:

   ✅ JSON `--format json` `--results.json` 
  
   ✅ YAML `--format yaml` `--results.yaml` 

---

## Requirements
- Python 3.7+
- Install dependencies:
  ```bash
  pip install requests

## Usage 
1) help options: 
```bash
python cve_fetcher.py --help
```
Output:
```bash
options:
  -h, --help            show this help message and exit
  --cve-id CVE_ID       fetch details of a specific CVE ID, (e.g: CVE-2025-1234
  --keyword KEYWORD     Filter CVEs by keyword in the description
  --since SINCE         Show CVEs published on or after this date (format: YYYY-MM-DD)
  --until UNTIL         Show CVEs published on or before this date (format: YYYY-MM-DD)
  --format {json,yaml}  output format for saving results (default: json)
  --output OUTPUT       Path to save the results
  --limit LIMIT         Number of CVEs to display (default: 5)
  --severity {LOW,MEDIUM,HIGH}
                        Filter CVEs by base severity
```

2) Default options: 
```bash
python cve_fetcher.py
```
Output:
```bash
CVE ID: CVE-1999-0095
The debug command in Sendmail is enabled, allowing attackers to execute commands as root.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*

CVE ID: CVE-1999-0082
CWD ~root command in ftpd allows root access.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:ftp:ftp:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:a:ftpcd:ftpcd:*:*:*:*:*:*:*:*

CVE ID: CVE-1999-1471
Buffer overflow in passwd in BSD based operating systems 4.3 and earlier allows local users to gain root privileges by specifying a long shell or GECOS field.

  Exploitability Score:  3.9
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:bsd:bsd:4.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:bsd:bsd:4.3:*:*:*:*:*:*:*

CVE ID: CVE-1999-1122
Vulnerability in restore in SunOS 4.0.3 and earlier allows local users to gain privileges.

  Exploitability Score:  3.9
  Base Severity: MEDIUM
  CPE: cpe:2.3:o:sun:sunos:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*

CVE ID: CVE-1999-1467
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the configuration of the nobody user.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3c:*:*:*:*:*:*:*
```
3) Filtering by CVE ID: 
```bash
python cve_fetcher.py --cve-id CVE-1999-1467
```
Output
```bash
CVE ID: CVE-1999-1467
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the configuration of the nobody user.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3c:*:*:*:*:*:*:*
```
4) Filtering by keyword: 
```bash
python cve_fetcher.py --keyword "Linux"
```
Output:
```
CVE ID: CVE-1999-0095
The debug command in Sendmail is enabled, allowing attackers to execute commands as root.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*

CVE ID: CVE-1999-0082
CWD ~root command in ftpd allows root access.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:ftp:ftp:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:a:ftpcd:ftpcd:*:*:*:*:*:*:*:*

CVE ID: CVE-1999-1471
Buffer overflow in passwd in BSD based operating systems 4.3 and earlier allows local users to gain root privileges by specifying a long shell or GECOS field.

  Exploitability Score:  3.9
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:bsd:bsd:4.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:bsd:bsd:4.3:*:*:*:*:*:*:*

CVE ID: CVE-1999-1122
Vulnerability in restore in SunOS 4.0.3 and earlier allows local users to gain privileges.

  Exploitability Score:  3.9
  Base Severity: MEDIUM
  CPE: cpe:2.3:o:sun:sunos:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*

CVE ID: CVE-1999-1467
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the configuration of the nobody user.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3c:*:*:*:*:*:*:*

C:\Users\rpais\Desktop\cve project>python cve_fetcher.py --cve-id CVE-1999-1467
dict_keys(['resultsPerPage', 'startIndex', 'totalResults', 'format', 'version', 'timestamp', 'vulnerabilities'])

CVE ID: CVE-1999-1467
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the configuration of the nobody user.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3c:*:*:*:*:*:*:*

C:\Users\rpais\Desktop\cve project>python cve_fetcher.py --keyword "Linux"
dict_keys(['resultsPerPage', 'startIndex', 'totalResults', 'format', 'version', 'timestamp', 'vulnerabilities'])

CVE ID: CVE-2000-0508
rpc.lockd in Red Hat Linux 6.1 and 6.2 allows remote attackers to cause a denial of service via a malformed request.

  Exploitability Score:  10.0
  Base Severity: MEDIUM
  CPE: cpe:2.3:o:debian:debian_linux:2.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:debian:debian_linux:2.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:mandrakesoft:mandrake_linux:6.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:mandrakesoft:mandrake_linux:6.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:mandrakesoft:mandrake_linux:7.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:redhat:linux:6.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:redhat:linux:6.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:redhat:linux:6.2:*:*:*:*:*:*:*

CVE ID: CVE-1999-0242
Remote attackers can access mail files via POP3 in some Linux systems that are using shadow passwords.

  Exploitability Score:  10.0
  Base Severity: HIGH
  CPE: cpe:2.3:o:slackware:slackware_linux:*:*:*:*:*:*:*:*

CVE ID: CVE-1999-0245
Some configurations of NIS+ in Linux allowed attackers to log in as the user "+".

  Exploitability Score:  3.9
  Base Severity: MEDIUM
  - User privileges obtainable:  True
  CPE: cpe:2.3:o:linux:linux_kernel:2.6.20.1:*:*:*:*:*:*:*

CVE ID: CVE-1999-0123
Race condition in Linux mailx command allows local users to read user files.

  Exploitability Score:  1.9
  Base Severity: LOW
  - User privileges obtainable:  True
  CPE: cpe:2.3:o:slackware:slackware_linux:3.0:*:*:*:*:*:*:*

CVE ID: CVE-1999-0316
Buffer overflow in Linux splitvt command gives root access to local users.

  Exploitability Score:  3.9
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:sam_lantinga:splitvt:*:*:*:*:*:*:*:*
```
5) Filtering by severity: 
```bash
python cve_fetcher.py --severity LOW
```
Output: 
```
CVE ID: CVE-1999-0095
The debug command in Sendmail is enabled, allowing attackers to execute commands as root.

  Exploitability Score:  10.0
  CPE: cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*

CVE ID: CVE-1999-0082
CWD ~root command in ftpd allows root access.

  Exploitability Score:  10.0
  CPE: cpe:2.3:a:ftp:ftp:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:a:ftpcd:ftpcd:*:*:*:*:*:*:*:*

CVE ID: CVE-1999-1471
Buffer overflow in passwd in BSD based operating systems 4.3 and earlier allows local users to gain root privileges by specifying a long shell or GECOS field.

  Exploitability Score:  3.9
  CPE: cpe:2.3:o:bsd:bsd:4.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:bsd:bsd:4.3:*:*:*:*:*:*:*

CVE ID: CVE-1999-1122
Vulnerability in restore in SunOS 4.0.3 and earlier allows local users to gain privileges.

  Exploitability Score:  3.9
  CPE: cpe:2.3:o:sun:sunos:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*

CVE ID: CVE-1999-1467
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the configuration of the nobody user.

  Exploitability Score:  10.0
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3c:*:*:*:*:*:*:*
```
6) Filtering by publication date
```bash
python cve_fetcher.py --since 2025-09-22
```
Output: 
```bash
CVE ID: CVE-1999-0095
The debug command in Sendmail is enabled, allowing attackers to execute commands as root.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*

CVE ID: CVE-1999-0082
CWD ~root command in ftpd allows root access.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:ftp:ftp:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:a:ftpcd:ftpcd:*:*:*:*:*:*:*:*

CVE ID: CVE-1999-1471
Buffer overflow in passwd in BSD based operating systems 4.3 and earlier allows local users to gain root privileges by specifying a long shell or GECOS field.

  Exploitability Score:  3.9
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:bsd:bsd:4.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:bsd:bsd:4.3:*:*:*:*:*:*:*

CVE ID: CVE-1999-1122
Vulnerability in restore in SunOS 4.0.3 and earlier allows local users to gain privileges.

  Exploitability Score:  3.9
  Base Severity: MEDIUM
  CPE: cpe:2.3:o:sun:sunos:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*

CVE ID: CVE-1999-1467
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the configuration of the nobody user.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:o:sun:sunos:4.0:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.1:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.2:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3:*:*:*:*:*:*:*
  CPE: cpe:2.3:o:sun:sunos:4.0.3c:*:*:*:*:*:*:*
```
6) Limiting output to 1
```bash
python cve_fetcher.py --limit 1
```
Output: 
```bash
CVE ID: CVE-1999-0095
The debug command in Sendmail is enabled, allowing attackers to execute commands as root.

  Exploitability Score:  10.0
  Base Severity: HIGH
  - Full System privilege obtainable:  True
  CPE: cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*
```

7) saving output
```bash
python cve_fetcher.py --format yaml --output results.yaml
python cve_fetcher.py --format json --output results.json
```
Output: 

Saves the results into a yaml or json file

![](https://i.imgur.com/YRJgSzR.png)
