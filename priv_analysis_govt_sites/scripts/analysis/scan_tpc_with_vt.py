#!/usr/local/bin/python3.8

import os, sys, json, re
import glob, requests
import csv
import time
#from urlparse import urlparse
from urllib.parse import urlparse

#Ref https://github.com/mozilla/openwpm-utils/blob/master/openwpm_utils/blocklist.py
from publicsuffix import PublicSuffixList
from abp_blocklist_parser import BlockListParser
import tldextract

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import scanner

master_data_in = []

#psl = PublicSuffixList()

in_file = '/tmp/govt_cookie_known_trackers.csv'
out_file = '/tmp/tpc_with_vt.csv'
out_file_full = '/tmp/tpc_with_vt_full.csv'

#easylist_gen_aggr = '/mnt/extra1/projects/govt_sites/rules/easylist_aggr.txt'

#easylist_aggr = BlockListParser(easylist_gen_aggr)

key_cache = {}

def get_tld_plus_one(site):
    ext = tldextract.extract(site)
    return ext.registered_domain

def read_csv_file(data_file):
   global key_cache
   input_file = csv.DictReader(open(data_file, encoding='ISO-8859-1'), delimiter='|')
   for row in input_file:
       fp = row['fp']
       tp = row['tp']
       if tp is None or fp is None: continue
       if tp == "" or fp == "": continue
       #if tp in ('.gov', '.gouv', '.go.'): continue
       if '.gov' in tp: continue
       if '.gouv' in tp: continue
       if '.go.' in tp: continue
       if 'us' in tp: continue

       #tp_re = re.search('.(.+)', tp)
       #if tp_re: tp = tp_re.group(1)

       fp_ext = get_tld_plus_one(fp)
       tp_ext = get_tld_plus_one(tp)
       if fp_ext == tp_ext: continue
       key = fp_ext + '#' + tp_ext
       if key in key_cache:
          continue
       else:
          key_cache[key] = 1
          master_data_in.append({'fp': 'http://' + fp_ext, 'tp': 'http://' + tp_ext})

def read_file(data_file):
   global master_data_in
   with open(data_file) as f:
       master_data_in = f.read().splitlines()

def process_tp_domains():
   global master_data_in
   f1 = open(out_file, "w+")
   f2 = open(out_file_full, "w+")
   for url in master_data_in:
      dom_re = re.search('://(.+)', url) 
      if dom_re:
          dom = dom_re.group(1)
          #url = "iyfsearch.com" #REMOVE
          #result_url =scanner.analyze_url_vt(url)
          result =scanner.analyze_domain_vt(dom)
          vt_short_status = result['mal_status']
          res = result['result']
          str1 = dom + "|" + str(json.dumps(vt_short_status))
          str2 = str(json.dumps(res))
          f1.write(str1+ "\n")
          f2.write(str2+ "\n")
          time.sleep(5)
          #break #REMOVE
   f1.close()
   f2.close()

def main():
   read_file(in_file)
   process_tp_domains()
   #print(master_data_in)

if __name__ == "__main__":
    main()

