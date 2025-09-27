```python
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
    "--since",
    help="Show CVEs published on or after this date (format: YYYY-MM-DD)"
)

parser.add_argument(
    "--until",
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
    response = requests.get(url)    #fetchs the URL
    response.raise_for_status()     #Checks fot HTTP errors
    data = response.json()          #parse JSON into a Python dictionary
    print(data.keys())
    filtered_results ={} # store filtered cve
    count = 0 #counter for --limit
# --------------------------------------------------------
# In case you need one CVE for testing and cba to retype the code
# --------------------------------------------------------
    #Finding all the fields in one CVE - uncomment this section if you need to check the values of one cve
    ##first_cve = data['vulnerabilities'][0]['cve']
    ##print(json.dumps(first_cve, indent=4)) #converting the dictionary to a formatted and readable string.

    for item in data ['vulnerabilities']: #loops through each item in vulnerabilities
        cve = item['cve']

        #Filtering by CVE ID argument --cve-id
        if args.cve_id and cve['id'] != args.cve_id:
            continue

        descriptions = cve['descriptions']

        # Filtering by key word in description argument --keyword
        if args.keyword:
            #checks if the keyword exists in any english description
            if not any(args.keyword.lower() in desc['value'].lower() for desc in descriptions if desc['lang'] == 'en'):
                continue
        print("\033[1m \nCVE ID:\033[0m", cve['id'])
           #only CVEs with english descriptions containing the keyword will be processed. IF no keywords, it skips the cve

        #printing the descriptions
        for desc in descriptions:
           if desc['lang'] =='en':
               print(desc['value'])


        #get the published date
        published_date_str =item.get('published', '')
        if published_date_str:
            published_date =datetime.fromisoformat(published_date_str.replace("Z", "+00:00")) #"Z", "+00:00" - ensures utc parsing
            #checks --since
            if args.since:
                since_date =datetime.fromisoformat(args.since)
                if published_date < since_date:
                    continue
            #check -- until
            if args.until:
                until_date =datetime.fromisoformat(args.until)
                if published_date > until_date:
                    continue

        #printing the exploitabilityScore and baseSeverity.
        metrics = cve.get('metrics', [])
        for metrics in metrics.get('cvssMetricV2', []):
            print("\n \033[1m Exploitability Score: \033[0m", metrics.get('exploitabilityScore'))
            baseSeverity = metrics.get('baseSeverity')
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

            if metrics.get('obtainAllPrivilege') :
                print("\033[1m  - Full System privilege obtainable: \033[0m", metrics.get('obtainAllPrivilege'))
            if metrics.get('obtainUserPrivilege') :
                print("\033[1m  - User privileges obtainable: \033[0m", metrics.get('obtainUserPrivilege'))
            if metrics.get('obtainOtherPrivilege') :
                print("\033[1m   - Other privileges obtainable: \033[0m", metrics.get('obtainOtherPrivilege'))
            if metrics.get('userInteractionRequired') :
                print("\033[1m   - User Interaction Required: \033[0m", metrics.get('userInteractionRequired'))

                # printing the configurations (Key: CpeMatch)
        for config in cve.get('configurations', []):  # loops through the configurations as a list
            for node in config.get('nodes', []):  # loops through the nodes
                for product in node.get('cpeMatch', []):  # same as above but in cpeMatch
                    print("\033[1m  CPE:\033[0m", product['criteria'])  # prints the value of the criteria key for that product

        #if the CVE passes all filters, add it to the results list
        filtered_results[cve['id']]= item
        count+=1

        #stops if limit is reached
        if args.limit and count >= args.limit:
            break

       #save filtered CVEs if -- output is provided
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
```
