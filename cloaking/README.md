# On Cloaking Behaviors of Malicious Websites

The source code (inclduing that of the crawler is based on https://www.sciencedirect.com/science/article/pii/S0167404820303874

The source code in *.js (nodejs) is based on Puppeteer 

Note: Replace VIRUSTOTAL_KEY_* with VirusTotal Key in scripts: feature_extract.py, identify_vuln_domains_links.py, identify_vuln_domains.py

* extract_ph_domains.py - Extract typo-squatting domains from DNSTwist (https://github.com/elceef/dnstwist)

* run_cloak.py - Run crawler on extracted sites

* feature_extract.py - Extract features/heuristics based on crawler output 

