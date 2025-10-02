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
  
    ✅ Publication dates (`--pubStartDate` and `--pubEndDate`)
  

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
  --pubStartDate        Show CVEs published on or after this date (format: YYYY-MM-DD)
  --pubEndDate         Show CVEs published on or before this date (format: YYYY-MM-DD)
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
python cve_fetcher.py --pubStartDate 2025-09-22 --pubEndDate 2025-10-02
```
Output: 
```bash
CVE ID: CVE-2025-10772
A vulnerability was identified in huggingface LeRobot up to 0.3.3. Affected by this vulnerability is an unknown functionality of the file lerobot/common/robot_devices/robots/lekiwi_remote.py of the component ZeroMQ Socket Handler. The manipulation leads to missing authentication. The attack can only be initiated within the local network. The vendor was contacted early about this disclosure but did not respond in any way.

  Exploitability Score:  6.5
  Base Severity: MEDIUM

CVE ID: CVE-2025-10773
A security flaw has been discovered in B-Link BL-AC2100 up to 1.0.3. Affected by this issue is the function delshrpath of the file /goform/set_delshrpath_cfg of the component Web Management Interface. The manipulation of the argument Type results in stack-based buffer overflow. The attack may be performed from remote. The exploit has been released to the public and may be exploited. The vendor was contacted early about this disclosure but did not respond in any way.

  Exploitability Score:  8.0
  Base Severity: HIGH
  CPE: cpe:2.3:o:lb-link:bl-ac2100_firmware:*:*:*:*:*:*:*:*
  CPE: cpe:2.3:h:lb-link:bl-ac2100:-:*:*:*:*:*:*:*

CVE ID: CVE-2025-10774
A weakness has been identified in Ruijie 6000-E10 up to 2.4.3.6-20171117. This affects an unknown part of the file /view/vpn/autovpn/sub_commit.php. This manipulation of the argument key causes os command injection. It is possible to initiate the attack remotely. The exploit has been made available to the public and could be exploited. The vendor was contacted early about this disclosure but did not respond in any way.

  Exploitability Score:  6.4
  Base Severity: MEDIUM

CVE ID: CVE-2025-10775
A security vulnerability has been detected in Wavlink WL-NU516U1 240425. This vulnerability affects the function sub_4012A0 of the file /cgi-bin/login.cgi. Such manipulation of the argument ipaddr leads to os command injection. It is possible to launch the attack remotely. The exploit has been disclosed publicly and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

  Exploitability Score:  6.4
  Base Severity: MEDIUM

CVE ID: CVE-2025-10776
A vulnerability was detected in LionCoders SalePro POS up to 5.5.0. This issue affects some unknown processing of the component Login. Performing manipulation results in cleartext transmission of sensitive information. The attack can be initiated remotely. The attack is considered to have high complexity. The exploitability is assessed as difficult. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

  Exploitability Score:  4.9
  Base Severity: LOW
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

## Current Limitations and known issues

- **Date Filtering**: The tool may return a 404 error if the API query uses pubStartDate or pubEndDate for very recent or future dates
  
- **Keyword Filtering**: Limited to English language

- **Limited Results**: defaults to fetching 5 cves per run unless user defines the limit

- **Same CVES returned**: Without a specific publication date( -- pubStartDate / -- pubEndDate) the script will always return the same 5 cves.

- **Limited to one attempt**: any network failures or API rate limits will are not automatically retried, the script will fail on first error.
