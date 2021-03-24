#!/usr/local/bin/python3.8

import warnings
warnings.filterwarnings('ignore')

import requests

import sys, os, json
import subprocess
import traceback
#import psycopg2
#import postgresql
from datetime import datetime,timedelta
import time
from datetime import timezone
import datetime
import re

import csv
import requests

# import nltk - a library for NLP analysis
from nltk import word_tokenize
from nltk.corpus import stopwords
from nltk import tag
#from autocorrect import spell
from autocorrect import Speller
from sys import platform

import mysql.connector
from mysql.connector import Error

from collections import OrderedDict
from collections import Counter
from multiprocessing import Process
import random
import whois
import tldextract
import socket
import pydig
import ipwhois
import pyasn
import math
#Ref: https://pythonhosted.org/python-geoip/
#Ref: https://stackoverflow.com/questions/54940411/typeerror-a-bytes-like-object-is-required-not-str-in-geolite2-function-in-py
#from geoip import open_database
from geoip import geolite2
from itertools import groupby

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import csv
import sys,os
import subprocess
#from dns import resolver
import dns
from bs4 import BeautifulSoup as beatsop

import base64
import io
import zipfile

import requests
from multiprocessing import Pool
from threading import Thread
from threading import Lock

from pytz import timezone
tz = timezone('EST')
import time;

mysql_user = 'root'
mysql_pwd = 'mysql'

def remove_file(filename):
   if os.path.exists(filename):
       os.remove(filename)

global_lock = Lock()
log_file = '/var/tmp/sq_dom_log_' + str(time.time())

remove_file(log_file)

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_m1/predictions.sql'

try:
    import Image
except ImportError:
    from PIL import Image

import pytesseract

def write_to_file(line):
    while global_lock.locked():
        sleep(0.01)
        continue

    global_lock.acquire()

    with open(log_file, "a+") as file:
        file.write(line)
        file.write("\n")
        file.close()

    global_lock.release()

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

def connect_source():
    """ Connect to MySQL database """
    #print("Connecting to mysql database [cs_certs]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            #print('Connected to MySQL database')
            return conn

    except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def connect_result():
    """ Connect to MySQL database """
    #print("Connecting to mysql database [cs_cert_results]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            #print('Connected to MySQL database')
            return conn

    except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)


def process_new_domains(dlist, dt):
   res_conn = None
   res_cursor = None

   dt_m = datetime.datetime.fromtimestamp(dt)

   try:
     res_conn = connect_result()
     res_cursor = res_conn.cursor()

     for domain in dlist:

       write_to_file(domain)
       cmd_str = '/mnt/extra1/projects/phishing/scripts_m1/1-Squatting-Domain-Identification/squatting_scan.py ' + domain
       output = subprocess.getoutput(cmd_str)
       #output = "[['health.com', 'combo'], ['healthcare.gov', 'combo']]"
       output = output.replace("'", '"')
       print(domain + ' -- ' + str(output))
       output_json = json.loads(output)
       for item in output_json:
          if len(item) == 0: continie
          seed = item[0]
          dtype = item[1]

          vals = (dt_m, domain, seed, dtype)
          #print(vals)
          query = 'INSERT IGNORE INTO sq_doms (datetime, domain, seed, type) VALUES (%s,%s,%s,%s)'
          res_cursor.execute(query, vals)

          res_conn.commit()

   except Exception as e:
     print(str(e))
     traceback.print_exc(file=sys.stdout)
   finally:
     if res_cursor is not None: res_cursor.close()
     if res_conn is not None: res_conn.close()

def chunks(l, n):
    """Yield n number of striped chunks from l."""
    for i in range(0, n):
        yield l[i::n]
    return l

def download_newly_registered_domains():
   #Ref: https://isc.sans.edu/forums/diary/Tracking+Newly+Registered+Domains/23127/
   time_yesterday = datetime.datetime.now(tz).timestamp() - 1*60*60*24
   date_yesterday = time.strftime('%Y-%m-%d', time.localtime(time_yesterday))
   date_yesterday_zip = date_yesterday + '.zip'
   #print(date_yesterday_zip)
   #Ref: https://stackoverflow.com/questions/8908287/why-do-i-need-b-to-encode-a-string-with-base64
   date_yesterday_base64_encoded = base64.b64encode(date_yesterday_zip.encode('utf-8'))
   #print(date_yesterday_base64_encoded)
   url = 'https://www.whoisds.com//whois-database/newly-registered-domains/' + str(date_yesterday_base64_encoded.decode('utf-8')) + '/nrd'
   #print(url)
   ua = "XmeBot/1.0 (https://blog.rootshell.be/bot/)"
   download_path = '/mnt/extra1/web_domains/workspace'
   download_file = download_path + '/' + 'new_doms_sq_' + date_yesterday_zip
   cmd = "/usr/bin/wget " + url + " -O " + download_file + " --user-agent=\"" + ua + "\""
   print("Running command: " + cmd)
   output = subprocess.getoutput(cmd) #REMOVE
   time.sleep(5) #REMOVE

   dom_list = []
   #Extract new domains from the zipped file
   with zipfile.ZipFile(download_file) as zf:
      with io.TextIOWrapper(zf.open("domain-names.txt"), encoding="utf-8") as f:
         for line in f.readlines():
            if not line: continue
            domain = line.strip()
            dom_list.append(domain)

   print("### Found " + str(len(dom_list)) + " new domains to process for " + str(date_yesterday) + " ...")
   chunk_list_gen = chunks(dom_list, 6)

   chunk_list_sub = []

   for item in chunk_list_gen:
      chunk_list_sub.append(item)

   result0 = Thread(target=process_new_domains, args=(chunk_list_sub[0], time_yesterday,))
   result1 = Thread(target=process_new_domains, args=(chunk_list_sub[1], time_yesterday,))
   result2 = Thread(target=process_new_domains, args=(chunk_list_sub[2], time_yesterday,))
   result3 = Thread(target=process_new_domains, args=(chunk_list_sub[3], time_yesterday,))
   result4 = Thread(target=process_new_domains, args=(chunk_list_sub[4], time_yesterday,))
   result5 = Thread(target=process_new_domains, args=(chunk_list_sub[5], time_yesterday,))

   result0.start()
   result1.start()
   result2.start()
   result3.start()
   result4.start()
   result5.start()

   result0.join()
   result1.join()
   result2.join()
   result3.join()
   result4.join()
   result5.join()

   time.sleep(3)

   #Remove zipped file
   if os.path.exists(download_file): os.remove(download_file) #REMOVE


def main():
   create_db()
   download_newly_registered_domains()
   #time_yesterday = datetime.datetime.now().timestamp() - 4*60*60*24  #* 2 #remove *2
   #date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday)) #time.localtime(utcnow_str))

   #time_today = datetime.datetime.now(tz).timestamp()
   #offset = 1
   #flag = True

   #time_rel = time_today - offset*60*60*24
   #new_dom_data = get_new_domains_from_mysql(time_rel)

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

