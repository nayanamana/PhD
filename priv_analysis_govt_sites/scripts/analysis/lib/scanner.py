#!/usr/bin/python3.7
import warnings
warnings.filterwarnings('ignore')


import sys, os, json
import subprocess
import traceback

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#import psycopg2
#import postgresql
from requests_html import HTMLSession
from datetime import datetime
import time
from datetime import timezone
import re

import csv

import mysql.connector
from mysql.connector import Error

from collections import OrderedDict
from multiprocessing import Process
import random
import requests

from pprint import pprint
from base64 import urlsafe_b64encode

#Ref: https://pypi.org/project/virustotal-python/
from virustotal_python import Virustotal
#from virustotal_python import VirustotalError

from pytz import timezone
tz = timezone('EST')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
#from heuristics import extract_heuristics

vt_api_key = <VIRUSTOTAL API KEY>

def analyze_url_vt(url):
   # v3 example
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")
   #vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v2")

   # v3 example
   result = {}
   try:
      # Send URL to VirusTotal for analysis
      resp = vtotal.request("urls", data={"url": url}, method="POST")
      # URL safe encode URL in base64 format
      # https://developers.virustotal.com/v3.0/reference#url
      url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
      # Obtain the analysis results for the URL using the url_id
      analysis_resp = vtotal.request(f"urls/{url_id}")
      #print(json.dumps(analysis_resp.data))
      #pprint(analysis_resp.object_type)
      analysis_data = analysis_resp.data
      if 'attributes' in analysis_data and 'last_analysis_stats' in analysis_data['attributes']:
      #    lbl_list = analysis_data['attributes']['last_analysis_stats']
      #    for lbl in lbl_list:
      #       if lbl_list[lbl] > 0 and lbl not in ['harmless', 'undetected', 'timeout']: result.append(lbl)
          engine_list = analysis_data['attributes']['last_analysis_results']
          #print(engine_list.values())
          #for engine in list(engine_list):
          #   print(engine)
          engine_list_vals = list(engine_list.values())
          #print(engine_list_vals[3])
          for item in engine_list_vals:
                 #print(item)
                 item_res = item['result']
                 item_cat = item['category']
                 if item_cat not in ['harmless', 'undetected', 'timeout']: 
                     if item_res not in result:
                         result[item_res] = 1
                     else:
                         result[item_res] += 1

   except Exception as err:
      #print(f"An error occurred: {err}\nCatching and continuing with program.")
      #traceback.print_exc(file=sys.stdout)
      pass
   #return list(result.keys())
   return result

def analyze_domain_vt(domain):
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")

   result = {}
   analysis_data = {}
   try:
      # Send URL to VirusTotal for analysis
      #resp = vtotal.request("urls", data={"url": url}, method="POST")
      # URL safe encode URL in base64 format
      # https://developers.virustotal.com/v3.0/reference#url
      #url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
      # Obtain the analysis results for the URL using the url_id
      analysis_resp = vtotal.request(f"domains/{domain}")
      #print(json.dumps(analysis_resp.data))
      #pprint(analysis_resp.object_type)
      analysis_data = analysis_resp.data
      #analysis_data_json = json.dumps(analysis_resp.data)
      #print(analysis_data)

      if 'attributes' in analysis_data and 'last_analysis_stats' in analysis_data['attributes']:
      #    lbl_list = analysis_data['attributes']['last_analysis_stats']
      #    for lbl in lbl_list:
      #       if lbl_list[lbl] > 0 and lbl not in ['harmless', 'undetected', 'timeout']: result.append(lbl)
          engine_list = analysis_data['attributes']['last_analysis_results']
          #print(engine_list.values())
          #for engine in list(engine_list):
          #   print(engine)
          engine_list_vals = list(engine_list.values())
          #print(engine_list_vals[3])
          for item in engine_list_vals:
                 #print(item)
                 item_res = item['result']
                 item_cat = item['category']
                 if item_cat not in ['harmless', 'undetected', 'timeout']:
                     if item_res not in result:
                         result[item_res] = 1
                     else:
                         result[item_res] += 1


   except Exception as err:
      #print(f"An error occurred: {err}\nCatching and continuing with program.")
      #traceback.print_exc(file=sys.stdout)
      pass
   #return list(result.keys())
   #results = analysis_data
   return {'mal_status': result, 'result': analysis_data}


