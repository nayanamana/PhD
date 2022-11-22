#!/home/naya/miniconda3/bin/python

import os
import subprocess
#import xml.etree.ElementTree as ET
import re
from base64 import urlsafe_b64encode

import xmltodict, json
#from bs4 import BeautifulSoup
#from urllib.parse import quote_plus
import requests
#from google_play_scraper import app
#import time

#from androguard.core.api_specific_resources import load_permission_mappings

import csv
import time

#import threading
import pprint
import sys
import traceback

#Ref: https://pypi.org/project/virustotal-python/
from virustotal_python import Virustotal
#from virustotal_python import VirustotalError
from pprint import pprint
from datetime import datetime


vt_api_key = VT_API_KEY

#source_sites_file = "/mnt/extra1/projects/religious_sites/master_data/domains"
#source_sites_file = "/mnt/extra1/projects/religious_sites/master_data/all_sites_filtered_part2.txt"
#source_sites_file = "/mnt/extra1/projects/religious_sites/tp_lists/tp_doms_scr.csv"
source_sites_file = "/mnt/extra1/projects/religious_sites/tp_lists/tp_doms_ck.csv"
#print(dump_file)

def get_dump_file():
   datetime_str = str(datetime.now())
   re_date = re.search('(\d\d\d\d)-(\d\d)-(\d\d)\s+(\d\d):(\d\d).+', datetime_str)
   date_part = ""
   if re_date:
        date_part = re_date.group(1) + re_date.group(2) + re_date.group(3) + re_date.group(4) + re_date.group(5)
   #dump_file = "/mnt/extra1/projects/religious_sites/dumps/vt_religious_dump_file_" + str(date_part) + ".csv"
   #dump_file = "/mnt/extra1/projects/religious_sites/dumps/tp_doms_scr_" + str(date_part) + ".csv"
   dump_file = "/mnt/extra1/projects/religious_sites/dumps/tp_doms_ck_" + str(date_part) + ".csv"
   return dump_file

def analyze_url_vt_1(domain, heu, rel_rank, dump_file):
   global vt_api_key
   #global dump_file

   vtotal = Virustotal(vt_api_key)

   #result = {}
   #analysis_data = {}
   categories = {}
   try:
      resp = vtotal.request(f"domains/{domain}")
      resp_json = resp.json()
      data_struct = {}
      no_eng_flagged_rel = 0
      no_eng_total = 0
      pct_eng_flagged_rel = 0

      #print(domain)
      #if "data" in resp_json and "attributes" in resp_json["data"] and "categories" in resp_json["data"]["attributes"]:
      if "data" in resp_json:
          data_struct = resp_json["data"]
          #print(data_struct)

          #for k in categories:
          #    val = categories[k]
          #    if 'religion' in val.lower():
          #        no_eng_flagged_rel += 1
          #no_eng_total = len(categories)
          #pct_eng_flagged_rel = round(no_eng_flagged_rel/no_eng_total*100,2) if no_eng_total != 0 else 0

      #categories_str = json.dumps(categories)
      #categories_str = categories_str.strip()

      #print_line = domain + "|" + heu + "|" + str(rel_rank) + "|" + str( no_eng_flagged_rel) + "|" + str(no_eng_total) + "|" + str(pct_eng_flagged_rel) + "|" + categories_str
      #print(print_line)

      with open(dump_file, 'a', encoding='utf-8') as f:
          f.write(json.dumps(data_struct) + "\n")


      #print(categories)

   except Exception as err:
       #print(str(err))
       pass

def process():
    global source_sites_file
    global dump_file

    #if os.path.exists(dump_file):
    #    os.remove(dump_file)

    lines = []
    with open(source_sites_file) as file:
        lines = file.readlines()

    incr = 0
    vt_counter = 19800
    sec_to_wait = 66400 # = 86400 (i.e., 3600x24) - 20000  

    #vt_counter = 3
    #sec_to_wait = 60

    dump_file = get_dump_file()

    for line in lines:
        incr += 1
        line = line.strip()

        re_line = re.search('(.+?)\s*(\(.+\))', line)
        if re_line:
           domain = re_line.group(1)
           heu = re_line.group(2)

           rel_rank = 0
           rel_re = re.search( 'Religion: (\d+)', heu)
           if rel_re:
               rel_rank = rel_re.group(1)
           #print(domain + " --- " + heu)
           #print(line)
           analyze_url_vt_1(domain, heu, rel_rank, dump_file)
        else:
           domain = line
           analyze_url_vt_1(domain, "", 0, dump_file)

        time.sleep(1)

        if incr % vt_counter == 0:
            time.sleep(sec_to_wait)
            dump_file = get_dump_file()

def main():
    process()


if __name__ == "__main__":
    main()
