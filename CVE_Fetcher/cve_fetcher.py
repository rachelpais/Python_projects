import requests #library that allows to make HTTP requests - Python script talks to website or APIs
import json, yaml
import argparse
from datetime import datetime

# --------------------------------------------------------
# URL
# --------------------------------------------------------
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --------------------------------------------------------
# Argparse Setup
# --------------------------------------------------------
parser = argparse.ArgumentParser(
    description ="Fetch and display CVE data from NVD" #creates a parser object and sets the rule for CLI inputs
    #description shows when the user runs python script.py --help and explains what the script does
)

parser.add_argument(
    "--cve-id",
    help="fetch details of a specific CVE ID, (e.g: CVE-2025-1234"
)

parser.add_argument(
    "--keyword",
    help="Filter CVEs by keyword in the description"
)

parser.add_argument(
    "--pubStartDate",
    help="Show CVEs published on or after this date (format: YYYY-MM-DD)"
)

parser.add_argument(
    "--pubEndDate",
    help="Show CVEs published on or before this date (format: YYYY-MM-DD)"
)

parser.add_argument(
    "--format",
    choices=["json", "yaml"],
    default="json",
    help="output format for saving results (default: json)"
)

parser.add_argument(
    "--output",
    help="Path to save the results"
)

parser.add_argument( #expects a number. If nothing is inputted then it will default to showing 5 CVES
    "--limit",
    type=int,
    default=5,
    help="Number of CVEs to display (default: 5)"
)

parser.add_argument( #Add another argument called severity and only accepts 3 words. Anything else it will error
    "--severity",
    choices =["LOW", "MEDIUM", "HIGH"],
    help = "Filter CVEs by base severity"
)

args = parser.parse_args() # Reads user's input

# --------------------------------------------------------
# Defining colours
# --------------------------------------------------------
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
END = "\033[0m" # Breaks the colour "loop"

# --------------------------------------------------------
# start of the try loop
# --------------------------------------------------------
try:
    # --------------------------------------------------------
    # Build request parameters for NVD API
    # --------------------------------------------------------
    params = {}

    if args.cve_id:
        params["cveId"] = args.cve_id

    if args.keyword:
        params["keywordSearch"] = args.keyword

    if args.pubStartDate:
        start_date = f"{args.pubStartDate}T00:00:00.000Z" # Start of the day
        params["pubStartDate"] = start_date

    if args.pubEndDate:
        end_date = f"{args.pubEndDate}T23:59:59.999Z"  # end of the day
        params["pubEndDate"] = end_date

    response = requests.get(url, params=params)    #fetches the URL with parameters
    response.raise_for_status()     #Checks for HTTP errors
    data = response.json()          #parse JSON into a Python dictionary

    filtered_results ={} # store filtered cve
    count = 0 #counter for --limit

    for item in data.get('vulnerabilities', []): #loops through each item in vulnerabilities
        cve = item['cve']

        #Filtering by CVE ID (already handled in params, but keep in case of local filter)
        if args.cve_id and cve['id'] != args.cve_id:
            continue

        descriptions = cve['descriptions']

        # Filtering by key word in description (extra check in case API returns extras)
        if args.keyword:
            if not any(args.keyword.lower() in desc['value'].lower() for desc in descriptions if desc['lang'] == 'en'):
                continue

        print("\033[1m \nCVE ID:\033[0m", cve['id'])

        #printing the descriptions
        for desc in descriptions:
            if desc['lang'] =='en':
                print(desc['value'])

        #printing the exploitabilityScore and baseSeverity.
        metrics = cve.get('metrics', {})
        for metric in metrics.get('cvssMetricV2', []):
            print("\n \033[1m Exploitability Score: \033[0m", metric.get('exploitabilityScore'))
            baseSeverity = metric.get('baseSeverity')
            if args.severity and args.severity != baseSeverity:
                continue

            if baseSeverity == "LOW":
                colour = GREEN
            elif baseSeverity == "MEDIUM":
                colour = YELLOW
            elif baseSeverity == "HIGH":
                colour = RED
            else:
                colour = END
            print(f"\033[1m  Base Severity: \033[0m{colour}{baseSeverity}{END}")

            if metric.get('obtainAllPrivilege'):
                print("\033[1m  - Full System privilege obtainable: \033[0m", metric.get('obtainAllPrivilege'))
            if metric.get('obtainUserPrivilege'):
                print("\033[1m  - User privileges obtainable: \033[0m", metric.get('obtainUserPrivilege'))
            if metric.get('obtainOtherPrivilege'):
                print("\033[1m   - Other privileges obtainable: \033[0m", metric.get('obtainOtherPrivilege'))
            if metric.get('userInteractionRequired'):
                print("\033[1m   - User Interaction Required: \033[0m", metric.get('userInteractionRequired'))

        # printing the configurations (Key: CpeMatch)
        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for product in node.get('cpeMatch', []):
                    print("\033[1m  CPE:\033[0m", product['criteria'])

        #if the CVE passes all filters, add it to the results list
        filtered_results[cve['id']] = item
        count += 1

        #stops if limit is reached
        if args.limit and count >= args.limit:
            break

    #save filtered CVEs if --output is provided
    if args.output:
        if args.format =="json":
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(filtered_results, f, indent=4)
        elif args.format =="yaml":
            with open(args.output, "w", encoding="utf-8") as f:
                yaml.dump(filtered_results, f, sort_keys=False)

        print("-" *100)
        print("-" * 100)

except requests.exceptions.RequestException as e:
    print ("Error: ", e)
