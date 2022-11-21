#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import print_function

import os
import os.path
import sys
import re
import json
import simplejson
import datetime
import traceback
from langdetect import detect
import requests
import robotparser
import socket
import sqlite3
import time

reload(sys)
sys.setdefaultencoding('utf8')


def is_mal_domain(domain_url):
   #return '[]'
   v_m = VIRUSTOTAL_KEY_M
   v_o = VIRUSTOTAL_KEY_0
   v_1 = VIRUSTOTAL_KEY_1
   v_2 = VIRUSTOTAL_KEY_2
   v_3 = VIRUSTOTAL_KEY_3
   v_4 = VIRUSTOTAL_KEY_4
   v_5 = VIRUSTOTAL_KEY_5
   v_6 = VIRUSTOTAL_KEY_6
   v_7 = VIRUSTOTAL_KEY_7
   v_8 = VIRUSTOTAL_KEY_8
   v_9 = VIRUSTOTAL_KEY_9
   v_10 = VIRUSTOTAL_KEY_10

   api_key = v_1
   baseurl = "https://www.virustotal.com/vtapi/v2/"

   resp_str = ""
   vuln = []
   try:
      url = baseurl + "url/report"
      #domain = 'http://' + domain.strip()
      params = {'apikey': api_key, 'resource': domain_url, 'allinfo': True }
      response = requests.post(url, data=params)
      resp_json = response.json()
      if ("scans" in resp_json and "resource" in resp_json):
         resource = resp_json['resource']
         scans = resp_json['scans']
         for vt in scans:
            if scans[vt]['detected'] == True:
                vt_result = str({vt: scans[vt]['result']})
                vuln.append(vt_result)
   except ValueError as e:
      print("Rate limit detected: " + str(e))
      traceback.print_exc(file=sys.stdout)
   except Exception as ex:
      print("Error detected: " + str(ex))
      traceback.print_exc(file=sys.stdout)

   return json.dumps(vuln)

### MAIN ###
user_dir = os.path.expanduser('~')
file_redir_urls = user_dir +  '/cloaking/data/redirected_urls'
file_out_vuln_urls = user_dir + '/cloaking/results/redirected_vuln_urls'
f_w = open(file_out_vuln_urls, "w+", 0 )
with open(file_redir_urls) as f_r:  
   for file in f_r:
      file = file.strip()
      vuln_result = is_mal_domain(file)
      f_w.write(file + '	' + str(vuln_result) + "\n")
      time.sleep(15)
f_w.close()

