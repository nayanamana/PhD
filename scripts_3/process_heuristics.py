#!/usr/local/bin/python3.8

import warnings
warnings.filterwarnings('ignore')

import sys, os, json
import subprocess
import traceback
from requests_html import HTMLSession

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#import psycopg2
#import postgresql
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
import pandas as pd
import numpy as np
import threading

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

import blacklists
import ct
from heuristics import extract_heuristics
import heuristics
from content import capture_content_ext

from pytz import timezone
tz = timezone('EST')

mysql_user = 'root'
mysql_pwd = 'mysql'
mysql_db = 'phishing_results_schema'

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_3/phishing_results_2.sql'

#phishtank_domains_len = 0
#openphish_domains_len = 0

def create_db():
   global pghost
   global db
   global postgres_user
   global db_create_sql_file

   print("Creating database/tables (if not exist)")

   cmd = '/usr/bin/mysql -u ' + mysql_user + ' -p' + mysql_pwd + ' < ' + db_create_sql_file
   print("Running command => " + cmd)
   output = subprocess.getoutput(cmd)
   print(output)
   print('--------------------------------------')

   """ Connect to MySQL database """
   print("Connecting to mysql database [phishing_results_schema]...")
   conn = None
   try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            print('Connected to MySQL database - phishing_results_schema')
            return conn

   except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def connect_result():
    """ Connect to MySQL database """
    #print("Connecting to mysql database [phishing_results_schema]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            #print('Connected to MySQL database - phishing_results_schema')
            return conn

    except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def create_chunks(list_name, n):
   #Ref: https://stackoverflow.com/questions/2659900/slicing-a-list-into-n-nearly-equal-length-partitions
   division = len(list_name) / float(n)
   return [ list_name[int(round(division * i)): int(round(division * (i + 1)))] for i in range(n) ]

def get_status_code(url):
   code = 999
   try:
      session = HTMLSession(verify=False)
      r = session.get(url,timeout=2)
      code = r.status_code
   except Exception as e:
      pass

   return code

def get_all_raw_mal_domain_data():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select distinct domain, url, cert, whois_info, detection_time from mal_raw_data where status=200 and url not in (select url from heuristics)")

  res_dict = {}
  result = cursor.fetchall()
  for d in result: 
      if d[1] not in res_dict:
         res_dict[d[1]] = {'domain': d[0], 'url': d[1], 'cert': d[2], 'whois_info': d[3], 'detection_time': d[4]}
  return res_dict

def get_all_raw_mal_content_data():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select distinct domain, url, content from mal_site_content where url not in (select url from heuristics)")

  res_dict = {}
  result = cursor.fetchall()
  for d in result: 
      if d[1] not in res_dict:
         res_dict[d[1]] = {'domain': d[0], 'url': d[1], 'content': d[2]}
  return res_dict

def get_all_raw_benign_domain_data():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select distinct domain, url, cert, whois_info, detection_time from benign_raw_data where status=200 and url not in (select url from heuristics)")

  res_dict = {}
  result = cursor.fetchall()
  for d in result:
      if d[1] not in res_dict:
         res_dict[d[1]] = {'domain': d[0], 'url': d[1], 'cert': d[2], 'whois_info': d[3], 'detection_time': d[4]}
  return res_dict


def get_all_raw_benign_content_data():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select distinct domain, url, content from benign_site_content where url not in (select url from heuristics)")

  res_dict = {}
  result = cursor.fetchall()
  for d in result:
    if d[1] not in res_dict:
       res_dict[d[1]] = {'domain': d[0], 'url': d[1], 'content': d[2]}
  return res_dict

def process_mal_heuristics():
   mal_domain_data = get_all_raw_mal_domain_data()
   mal_content_data = get_all_raw_mal_content_data()
  
   conn = connect_result()
   cursor = conn.cursor()
   counter = 0

   for url in mal_domain_data:
    try:
      detection_time =  mal_domain_data[url]['detection_time']
      domain = mal_domain_data[url]['domain']
      cert = mal_domain_data[url]['cert']
      raw_whois_info = mal_domain_data[url]['whois_info']
      raw_whois_info_obj = json.loads(raw_whois_info) if raw_whois_info else {}
      whois_info = heuristics.get_processed_whois_info(detection_time,domain,raw_whois_info_obj)

      if url not in mal_content_data: continue
      content = mal_content_data[url]['content']

      h_dom = heuristics.extract_heuristics(domain, cert,whois_info)
      #print(h_dom)
      h_content = heuristics.extract_content_heuristics(content, domain)
      h_combined = h_dom.copy()
      h_combined.update(h_content)

      try:
         #print('---------------------')
         #print(url)
         vals = (domain, url, json.dumps(h_combined), 1)
         query = 'INSERT IGNORE INTO heuristics (domain, url, heuristics, is_phish) values (%s,%s,%s,%s)'
         cursor.execute(query, vals)
         #if counter%10 == 0: conn.commit()
         conn.commit()
         counter += 1
      except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
    except Exception as e:
       print(str(e))
       traceback.print_exc(file=sys.stdout)

   try:
      if cursor is not None: cursor.close()
      if conn is not None: conn.close()
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)
          

def process_benign_heuristics():
   benign_domain_data = get_all_raw_benign_domain_data()
   benign_content_data = get_all_raw_benign_content_data()

   conn = connect_result()
   cursor = conn.cursor()
   counter = 0

   for url in benign_domain_data:
    try:
      detection_time =  benign_domain_data[url]['detection_time']
      domain = benign_domain_data[url]['domain']
      cert = benign_domain_data[url]['cert']
      raw_whois_info = benign_domain_data[url]['whois_info']
      raw_whois_info_obj = json.loads(raw_whois_info) if raw_whois_info else {}
      whois_info = heuristics.get_processed_whois_info(detection_time,domain,raw_whois_info_obj)

      if url not in benign_content_data: continue
      content = benign_content_data[url]['content']

      h_dom = heuristics.extract_heuristics(domain, cert,whois_info)
      #print(h_dom)
      h_content = heuristics.extract_content_heuristics(content, domain)
      h_combined = h_dom.copy()
      h_combined.update(h_content)

      try:
         #print('---------------------')
         #print(url)
         vals = (domain, url, json.dumps(h_combined), 0)
         query = 'INSERT IGNORE INTO heuristics (domain, url, heuristics, is_phish) values (%s,%s,%s,%s)'
         cursor.execute(query, vals)
         #if counter%10 == 0: conn.commit()
         conn.commit()
         counter += 1
      except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
    except Exception as e:
       print(str(e))
       traceback.print_exc(file=sys.stdout)

   try:
      if cursor is not None: cursor.close()
      if conn is not None: conn.close()
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def run_in_parallel(*fns):
  proc = []
  for fn in fns:
    p = Process(target=fn)
    p.start()
    proc.append(p)
  for p in proc:
    p.join()

def main():
      
   create_db()
   
   #process_mal_heuristics() 
   #process_benign_heuristics()
         
         
   #m_1 = Process(target=process_mal_heuristics)
   #m_1.start()
   #b_1 = Process(target=process_benign_heuristics)
   #b_1.start()

   #m_1.join()
   #b_1.join()

   #Ref: https://stackoverflow.com/questions/7168508/background-function-in-python
   mal_thread = threading.Thread(target=process_mal_heuristics, name="mal") #, args=some_args)
   mal_thread.start()

   benign_thread = threading.Thread(target=process_benign_heuristics, name="benign") #, args=some_args)
   benign_thread.start()
   
   #run_in_parallel(process_mal_heuristics,process_benign_heuristics)

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

