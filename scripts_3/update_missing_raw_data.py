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

def get_unprocessed_mal_raw_domains():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select domain, url whois_info from mal_raw_data where  DATE(detection_time) > (DATE(NOW()) - INTERVAL 5 DAY) and status=200 and whois_info='{}'")
  res_list = []
  result = cursor.fetchall()
  for d in result: res_list.append({'url':d[1], 'domain':d[0]})
  return res_list

def get_unprocessed_benign_raw_domains():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select domain,url whois_info from benign_raw_data where  DATE(detection_time) > (DATE(NOW()) - INTERVAL 5 DAY) and status=200 and whois_info='{}'")
  res_list = []
  result = cursor.fetchall()
  for d in result: res_list.append({'url':d[1],'domain':d[0]})
  return res_list

def process_unprocessed_mal_raw_domains():
   unprocessed_mal_raw_domains = get_unprocessed_mal_raw_domains()
   for u_obj in unprocessed_mal_raw_domains:
       url = u_obj['url']
       domain = u_obj['domain']
       conn = None
       cursor = None
       try:
          conn = connect_result()
          cursor = conn.cursor()
          whois_info = heuristics.extract_whois_info(domain)
          whois_info_json = json.dumps(whois_info) if whois_info else '{}'
          vals = (whois_info_json, url)
          query = "update mal_raw_data set whois_info=%s where url=%s"
          cursor.execute(query, vals)
          conn.commit()
          print("URL: " + url + " processed...")
          print(whois_info_json)
       except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
       finally:
         if conn is not None: conn.commit()
         if cursor is not None: cursor.close()
         if conn is not None: conn.close()

def process_unprocessed_benign_raw_domains():
   unprocessed_benign_raw_domains = get_unprocessed_benign_raw_domains()
   for u_obj in unprocessed_benign_raw_domains:
       url = u_obj['url']
       domain = u_obj['domain']
       conn = None
       cursor = None
       try:
          conn = connect_result()
          cursor = conn.cursor()
          whois_info = heuristics.extract_whois_info(domain)
          whois_info_json = json.dumps(whois_info) if whois_info else '{}'
          vals = (whois_info_json, url)
          query = "update benign_raw_data set whois_info=%s where url=%s"
          cursor.execute(query, vals)
          conn.commit()
          print("URL: " + url + " processed...")
          print(whois_info_json)
       except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
       finally:
         if conn is not None: conn.commit()
         if cursor is not None: cursor.close()
         if conn is not None: conn.close()
 

def main():
      
   create_db()

   #process_unprocessed_mal_raw_domains()
   #process_unprocessed_benign_raw_domains()
   
         
   p_1 = Process(target=process_unprocessed_mal_raw_domains)
   p_1.start()
    
   b_1 = Process(target=process_unprocessed_benign_raw_domains)
   b_1.start()

   p_1.join()
   b_1.join()
    
   

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

