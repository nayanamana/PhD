import warnings
warnings.filterwarnings('ignore')

import sys,sys,json,os
from requests_html import HTMLSession
from seleniumwire import webdriver  # Import from seleniumwire
from selenium.webdriver.firefox.options import Options
from datetime import datetime
import gzip

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import subprocess
import traceback
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

def get_all_active_mal_domains():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select domain, url from mal_domains where status=200 and url not in (select url from mal_site_content)")

  res_list = []
  result = cursor.fetchall()
  for r in result: 
     res_list.append({'domain': r[0], 'url': r[1]})
  return res_list

def get_all_active_benign_domains():
  conn = connect_result()
  cursor = conn.cursor()
  cursor.execute("select domain, url from benign_domains where url not in (select url from benign_site_content)")

  res_list = []
  result = cursor.fetchall()
  for r in result:
     res_list.append({'domain': r[0], 'url': r[1]})
  return res_list

def print_time():
   now = datetime.now()
   current_time = now.strftime("%H:%M:%S")
   return ("Current Time =", current_time)

#print(arg)
def get_status_code(url):
   try:
      session = HTMLSession(verify=False)
      r = session.get(url,timeout=2)
      if r.status_code == 200:
         return r.status_code
   except Exception as e:
      pass
   return 999

def compress_text(text):
    return gzip.compress(bytes(text,'utf-8'))

def decompress_text(text):
    return gzip.decompress(text).decode('utf-8')

def process_mal_site_content():
   res = get_all_active_mal_domains()
   res = list(res)

   for d_obj in res:
       try:
          capture_content(d_obj['domain'], d_obj['url'], 1) 
       except Exception as e:
          #print("######## Could not make request to: " + d_obj['url'])
          pass

def capture_content_ext(domain, url, is_phish):
   try:
      #Ref: https://stackoverflow.com/questions/51762655/how-to-ignore-an-invalid-ssl-certificate-with-requests-html
      session = HTMLSession(verify=False)
      resp = session.get(url,timeout=2)
      content_text = resp.html.html

      try:
         conn = connect_result()
         cursor = conn.cursor()
         vals = (domain, url, content_text)
         table = 'mal_site_content' if is_phish else 'benign_site_content'
         query = 'INSERT IGNORE INTO ' + table + ' (domain, url, content) VALUES (%s,%s,%s);'
         cursor.execute(query, vals)
         conn.commit()
      except Exception as e:
          traceback.print_exc(file=sys.stdout)
          pass
      finally:
          conn.close()



   except Exception as e:
       print(str(e))
       traceback.print_exc(file=sys.stdout)
       pass


def capture_content(domain, url, is_phish):
   try:
	   # Create a new instance of the Firefox driver
	   options = Options()
	   options.headless = True
	   driver = webdriver.Firefox(options=options)

	   # Go to the Google home page
	   driver.get(url)

	   table = 'mal_site_content' if is_phish == 1 else 'benign_site_content' 

	   # Access requests via the `requests` attribute
	   for request in driver.requests:
	      if request.response and request.response.headers:
                try:
                   allowed_headers = ['text/html','text/css','text/javascript']
                   if not ('Content-Type' in request.response.headers and request.response.headers['Content-Type'] in allowed_headers): continue
                   if not hasattr(request, 'url'): continue
                   dep_url = request.url
                   content_type = request.response.headers['Content-Type']
                   content = request.response.body.decode('utf-8') if request.response.body else ''

                   conn = None
                   try:
                      conn = connect_result()
                      cursor = conn.cursor()
                      vals = (domain, url, dep_url, content_type, content)
                      query = 'INSERT IGNORE INTO ' + table + ' (domain, url, dep_url, content_type, content) VALUES (%s,%s,%s,%s,%s);'
                      cursor.execute(query, vals)
                      conn.commit()
                   except Exception as e:
                      #traceback.print_exc(file=sys.stdout)
                      pass
                   finally:
                      conn.close()
                except Exception as e:
                    #traceback.print_exc(file=sys.stdout)
                    pass
	   driver.close()
   except Exception as e:
       print("######## Could not make request to: " + url)
       pass
      

