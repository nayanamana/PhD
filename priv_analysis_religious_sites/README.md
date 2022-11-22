# No Salvation from Trackers: Privacy Analysis of Religious Websites and Mobile Apps

This work is based on https://users.encs.concordia.ca/~mmannan/publications/Religious-sites-DPM2022.pdf

* demo.py - Script to crawl religious websites using OpenWPM
* eval_trackers.py - Identify tracking information from the data extracted from the OpenWPM database
* scan_all_religious_sites_with_vt.py - Scan religious sites with VirusTotal (replace the VirusTotal API Key: VT_API_KEY with the actual key)
* scan_with_wapiti.py - Identify security issues by scanning the religious sites with Wapiti scanner. Wapiti scanner needs to be installed (usually installed in /usr/local/bin/wapiti) from https://github.com/wapiti-scanner/wapiti, before running this script.
