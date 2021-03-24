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

try:
    import Image
except ImportError:
    from PIL import Image

import pytesseract

from bs4 import BeautifulSoup

#Ref: https://stackoverflow.com/questions/8989457/dnspython-setting-query-timeout-lifetime
resolver = dns.resolver.Resolver()
resolver.timeout = 1
resolver.lifetime = 1

from requests_html import HTMLSession

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import seaborn as sns; sns.set_theme()

#import preprocessing from sklearn
from sklearn import preprocessing

# Using Skicit-learn to split data into training and testing sets
from sklearn.model_selection import train_test_split

# Import the model we are using
from sklearn.ensemble import RandomForestRegressor

# Import tools needed for visualization
from sklearn.tree import export_graphviz
import pydot

#Disable warnings
pd.options.mode.chained_assignment = None  # default='warn'

# Import matplotlib for plotting and use magic command for Jupyter Notebooks
import matplotlib.pyplot as plt
#%matplotlib inline

from sklearn.preprocessing import OneHotEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.compose import make_column_transformer
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import FunctionTransformer
from sklearn.neighbors import KNeighborsClassifier

import pickle
import urllib.request

from urllib.parse import urlparse
from threading import Thread
#import sys
import queue
import urllib.request
import os.path

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import feature_extract
import blacklists
import utils
import ct
from heuristics import extract_heuristics
from ml_fn import *
import predict
import WORD_TERM_KEYS

import heuristics
import signal

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from pytz import timezone
tz = timezone('EST')


FILTER_KEYS =  WORD_TERM_KEYS.FILTER_KEYS

#Ref: https://stackoverflow.com/questions/2281850/timeout-function-if-it-takes-too-long-to-finish
class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)

cur_time_day = datetime.now().timestamp()
cur_day_str = time.strftime('%d%m%Y', time.localtime(cur_time_day))

predict_dir = '/mnt/extra1/web_domains/workspace/predict_src_p/'  + str(cur_day_str)

if not os.path.exists(predict_dir):
    os.makedirs(predict_dir)

#Remove screenshots+html
for f in os.listdir(predict_dir):
   if f.endswith('.png') or f.endswith('.html') or f.endswith('.txt'):
      os.remove(os.path.join(predict_dir, f))

threshold_days = 7
concurrent = 200
working_urls = []

url_limit = 25000 #000

q = queue.Queue(concurrent * 2)

#geo_db = open_database('/mnt/extra1/projects/phishing/data/GeoLite2-Country_20200818/GeoLite2-Country.mmdb')

mysql_user = 'root'
mysql_pwd = 'mysql'
#mysql_db = 'cs_cert_results'

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_m1/predictions.sql'
if not os.path.exists(predict_dir):
    os.makedirs(predict_dir)
#Remove screenshots
for f in os.listdir(predict_dir):
   if f.endswith('.png'):
      os.remove(os.path.join(predict_dir, f))

asndb = pyasn.pyasn('/mnt/extra1/projects/phishing/data/ipasn.dat')

model_dir = '/mnt/extra1/projects/phishing/scripts_m1/saved_models'
skipped_sites_log = '/mnt/extra1/projects/phishing/scripts_m1/data/skipped_sites.log_p_' + str(cur_day_str)

#data_h_path = '/mnt/extra1/projects/phishing/data/predict_heuristics.csv'
#data_path = '/mnt/extra1/projects/phishing/data/predictions.csv'
#data_path1 = '/mnt/extra1/projects/phishing/data/predictions1.csv'

chrome_driver_path = '/mnt/extra1/projects/phishing/drivers/chromedriver'

simhashes_to_skip = [
              '1805800038487239398', #<html><head></head><body>Table 'xmailv3_store.wrongstocklink' doesn't exist</body></html>
              '8906118505739837662', #<html><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">Too many requests</pre></body></html>
              '1437922443512693402', #If you want your website to be available on the Internet, open your webmasters panel and in the general settings page turn on websites availability
              '9211276104574665357',
              '540231057390865174' #<p align="center"><font face="Arial, Helvetica, sans-serif" size="+2" color="#0033CC"><b><font face="Verdana, Arial, Helvetica, sans-serif" color="#003399"> Sito web in manutenzione</font></b></font></p>
             ]
simhashes_to_skip = [x[:-1] for x in simhashes_to_skip]

#h_labels = ['is_pop_dom_in_domain','is_sensitive_keyword_in_domain','has_out_of_position_tlds','longest_word_in_dom_ratio','contains_hyphens_and_digits','randomness_score','domain_length','sen_input_feilds','has_bad_action_fields','has_popular_terms_in_tfidf','hash_pop_dom_in_copyright','links_to_login_pages']
h_labels = ['is_pop_dom_in_domain','is_sensitive_keyword_in_domain','has_out_of_position_tlds','lw1','lw2','lw3','lw4','lw5','lw6','lw7','lw8','lw9','lw10','contains_hyphens_and_digits','randomness_score','domain_length', 'sen_input_feilds','has_bad_action_fields','has_popular_terms_in_tfidf'] #,'hash_pop_dom_in_copyright', 'has_links_to_login_pages']

#Ref: https://stackoverflow.com/questions/49820228/how-to-compare-the-similarity-of-documents-with-simhash-algorithm
def split_hash(str, num):
    return [ str[start:start+num] for start in range(0, len(str), num) ]

def filter_by_key_phrases(html_file):
   content = ""
   with open(html_file) as f:
      content = f.readlines()
   content_str = ""
   for line in content:
      line = line.strip()
      content_str += line

   soup = beatsop(content_str)

   title = soup.title.text.lower() if soup.title is not None else ""
   title = title.strip()
   if 'Account Suspended'.lower() in title: return 'Account Suspended'.lower()
   if 'error' in title: return 'error'.lower()
   if 'DNS, Dynamic DNS, VPN, VPS and Web Hosting Provider'.lower() in title: return 'DNS, Dynamic DNS, VPN, VPS and Web Hosting Provider'.lower()
   if 'Index of /'.lower() in title: return 'Index of /'.lower()
   if '400 Bad Request'.lower() in title: return '400 Bad Request'.lower()
   if 'Domains, Webspace, Domain Webhosting, Server-Hosting Provider'.lower() in title: return 'Domains, Webspace, Domain Webhosting, Server-Hosting Provider'.lower()
   if 'Expired or Suspended'.lower() in title: return 'Expired or Suspended'.lower()
   if 'web hosting'.lower() in title: return  'web hosting'.lower() #<title>site44 - absurdly simple web hosting</title>
   if 'Contact Support'.lower() in title: return 'Contact Support'.lower()
   if 'Free Website'.lower() in title: return 'Free Website'.lower() #<title>Welcome to messagealertsupportmailalertconnecthomenslbnhj.000webhostapp.com Free Website</title>

   if 'This domain is registered at'.lower() in content_str.lower(): return 'This domain is registered at'.lower()
   if 'contact your hosting provider'.lower() in content_str.lower(): return 'contact your hosting provider'.lower() #If you are the owner of this website, please contact your hosting provider
   if 'data-adblockkey="MFww'.lower() in content_str.lower(): return 'data-adblockkey="MFww'.lower() #data-adblockkey="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALquDFETXRn0Hr05fUP7EJT77xYnPmRbpMy4vk8KYiHnkNpednjOANJcaXDXcKQJN0nXKZJL7TciJD
   if 'Your domain name is not added to the database'.lower() in content_str.lower(): return 'Your domain name is not added to the database'.lower()
   if 'If you want your website to be available on the Internet, open your webmasters panel and in the general settings page turn on websites availability'.lower() in content_str.lower(): return 'If you want your website to be available on the Internet'.lower()
   if '<span class="related-searches-custom">Related Searches:</span>'.lower() in content_str.lower(): return '<span class="related-searches-custom">'.lower()
   if 'failed to open stream'.lower() in content_str.lower(): return 'failed to open stream'.lower() #<b>Warning</b>:  Unknown: failed to open stream: Permission denied in <b>Unknown</b> on line <b>0</b><br>
   if 'This link is currently unavailable'.lower() in content_str.lower(): return 'This link is currently unavailable'.lower() #<html><head></head><body><div align="center" style="font-size:12px;margin-top:40px;">This link is currently unavailable.<!-- err3 --></div></body></html>

   if "coming soon".lower() in content_str.lower(): return "coming soon".lower()
   if "opening soon".lower() in content_str.lower(): return "opening soon".lower()
   if "webpackJsonpparking-lander".lower() in content_str.lower(): return "webpackJsonpparking-lander".lower()
   if "web hosting".lower() in content_str.lower(): return "web hosting".lower()
   if "is For Sale".lower() in content_str.lower(): return "is For Sale".lower()
   if "free domain name".lower() in content_str.lower(): return "free domain name".lower() 
   if "parked domain".lower() in content_str.lower(): return "parked domain".lower()
   if "EN CONSTRUCTION".lower() in content_str.lower(): return "EN CONSTRUCTION".lower()
   if "under construction".lower() in content_str.lower(): return "under construction".lower()
   if "checkdomain".lower() in content_str.lower(): return "checkdomain".lower()
   if "parking".lower() in content_str.lower(): return "parking".lower()
   if "sell domain".lower() in content_str.lower(): return "sell domain".lower()
   if "sell a domain".lower() in content_str.lower(): return "sell a domain".lower()
   if "buy domain".lower() in content_str.lower(): return "buy domain".lower()
   if "buy a domain".lower() in content_str.lower(): return "buy a domain".lower()
   if "Domains For Sale".lower() in content_str.lower(): return "Domains For Sale".lower()
   if "This site can’t be reached".lower() in content_str.lower() or "DNS_PROBE_FINISHED_NXDOMAIN".lower() in content_str.lower(): return "This site can’t be reached_DNS_PROBE_FINISHED_NXDOMAIN".lower()
   if "Activate your domain".lower() in content_str.lower(): return "Activate your domain".lower()

   #skip by language
   if 'lang=' in content_str.lower() and 'lang="en' not in content_str.lower(): return 'lang='

   if '<body></body>' in content_str.lower(): return '<body></body>'

   #if 'Your session has expired'.lower() in content_str.lower(): return 1

   return 0

def file_by_simhash(simhash_stripped):
   global simhashes_to_skip
   if simhash_stripped in simhashes_to_skip: return 1
   return 0

def resolve_dns(host):
   #Ref: https://stackoverflow.com/questions/34376244/batch-bulk-dns-lookup-in-python
   try:
      resolver.query(host, 'A')
   except Exception as e:
      return False
   return True

#Ref: https://stackoverflow.com/questions/1949318/checking-if-a-website-is-up-via-python
#Ref: https://stackoverflow.com/questions/27324494/is-there-any-timeout-value-for-socket-gethostbynamehostname-in-python
def is_web_domain_online(host):
    """ This function checks to see if a host name has a DNS entry by checking
        for socket info. If the website gets something in return, 
        we know it's available to DNS.
    """
    try:
        #with raise_on_timeout(5): # Timeout in 100 milliseconds
        socket.gethostbyname(host)
    except Exception as e:
        return False
    else:
        return True

def doWork():
    while True:
        url_obj = q.get()
        status, url = getStatus(url_obj['domain'])
        if status != "error":
          doSomethingWithResult(url_obj)
        q.task_done()
        #if len(working_urls)>url_limit: break

def getStatus(domain):
    try:
        with urllib.request.urlopen('http://' + domain, timeout=2) as response:
          return response.status,domain
    except:
        return "error", domain

def doSomethingWithResult(url_obj):
    working_urls.append(url_obj)
    working_urls_length = len(working_urls)
    if working_urls_length%100==0:
       print("### " + str(working_urls_length) + " working domains processed")

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
   #print('-------------------------------------')

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

def url_ok(url):
    try:
       #r = requests.head(url,allow_redirects=False)
       with urllib.request.urlopen(url, timeout=2) as response:
          return response.status == 200
    except Exception as e:
       print("### URL not OK: " + url + " --- " + str(e))
       return False

def check_url(dom):
   #dom = 'lankapage.com'
   url = 'https://' + dom
   is_https = 0
   code = 999
   content_text = ""

   try:
      url = 'https://' + dom
      #Ref: https://stackoverflow.com/questions/56691190/requests-html-httpsconnectionpoolread-timed-out
      session = HTMLSession(verify=False)
      r = session.get(url, timeout=10)
      #if r.status_code == 200:
      if int(str(r.status_code)[:1]) < 4:
         is_https = 1
         code = r.status_code
         content_text = r.html.html
   except Exception as e:
      print(str(e))
      pass

   if is_https == 0:
      try:
         url = 'http://' + dom
         session = HTMLSession(verify=False)
         r = session.get(url, timeout=10)
         is_https = 0
         code = r.status_code
         content_text = r.html.html
      except Exception as e:
         #print(str(e))
         pass


   return {'is_https': is_https, 'code': code, 'content': content_text, 'url': url}


def get_status_code(url):
   code = 999
   try:
      r = requests.head(url, allow_redirects=True, timeout=1)
      code = r.status_code
   except requests.exceptions.Timeout as e:
      print(str(e))
      pass
   except Exception as e:
      print(str(e))
      pass
   return code

def is_parked_domain_page(content):
   filter_list = ['window.LANDER_SYSTEM', 'This domain was recently registered', 'We offer affordable hosting', 'Are you interested in this name', 'recover your domain', 'find similar domains']
   filter_list.extend(FILTER_KEYS)
   filter_list =  [each_string.lower() for each_string in filter_list]

   res = [ele for ele in filter_list if (ele.lower() in content.lower())]
   if res:
      return 1
   return 0

def save_site(domain, url, out_dir):
 d = None
 vp_width = 1200
 vp_height = 900

 #url = url.replace('https','http') #REMOVE
 #print(url)

 try:
   chrome_options = Options()
   chrome_options.add_argument('--headless')
   chrome_options.add_argument('--no-sandbox')
   chrome_options.add_argument('--disable-dev-shm-usage')
   chrome_options.add_argument('--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36"')
   d = webdriver.Chrome('/mnt/extra1/projects/phishing/drivers/chromedriver',chrome_options=chrome_options)
   d.set_window_size(vp_width, vp_height)
   d.set_page_load_timeout(30)
   #d.set_page_load_timeout(15)
   d.get(url)
   final_url = d.current_url
   ext_final_url = tldextract.extract(final_url)
   if ext_final_url and ext_final_url.domain in feature_extract.get_alexa_doms_sld():
       write_to_skipped_log("redirected to popular domain  -- " + domain)
       raise Exception("redirected to popular domain  -- " + domain)

   page_source = d.page_source
   with open(out_dir + '/' + domain + '.html', 'w+') as f:
      f.write(d.page_source)
   d.save_screenshot(out_dir + '/' + domain + '.png')
   d.quit()
 except Exception as e:
   print(str(e))
   traceback.print_exc(file=sys.stdout)
 finally:
   try:
     d.close()
   except Exception as e:
      pass

def is_skip_page(text):
    """
    :param img_path:
    :return:
    This part is to extract words from an image. We apply OCR technique to read texts from images.
    More info on OCR can be found:
    https://github.com/madmaze/pytesseract
    """
    for ele in FILTER_KEYS:
       if text:
          if ele.lower() in text.lower():
              return 1
    return 0

def remove_file(file_path):
   if os.path.exists(file_path): os.remove(file_path)

def remove_site_files(domain):
   img_path = predict_dir + '/' + domain  + '.png'
   html_path = predict_dir + '/' + domain  + '.html'
   try:
      if os.path.exists(img_path): os.remove(img_path)
      if os.path.exists(html_path): os.remove(html_path)
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def print_date():
   now = datetime.now()
   return str(now.strftime("%Y-%m-%d %H:%M:%S"))

#retrn true if no form inpult fields
def is_filter_html_input_fields(html_file):
   #Filter html files with input fields
   #Ref: https://stackoverflow.com/questions/17226080/parsing-html-forms-input-tag-with-beautiful-soup
   content = ""
   with open(html_file) as f:
      content = f.readlines()
   content_str = ""
   for line in content:
      line = line.strip()
      content_str += line
   soup = beatsop(content_str)
   txt_input = soup.findAll('input')
   if len(txt_input) == 0: return 1

   return 0

def write_to_skipped_log(line):
   with open(skipped_sites_log, 'a+') as the_file:
       the_file.write(line  + '\n')

def get_new_domains_from_mysql(date_str, limit):

   #sql = "SELECT domain, cert from new_doms_" + date_today  + " limit 10"# #REMOVE
   sql = "SELECT domain, cert from new_doms_" + date_str  + " order by rand() limit " + str(limit)# #REMOVE
   print(sql)

   conn = None
   cursor = None

   dom_list = []

   try:
     #connect to mysql database
     conn = connect_source()
     cursor = conn.cursor()

     res_conn = connect_result()
     res_cursor = res_conn.cursor()

     counter = 0

     print("Getting new domains from table: 'new_doms' for date: '" + str(date_str) + "'")

     cursor.execute(sql)
     result_set = cursor.fetchall()

     for d in result_set:
         if counter > limit: break
         dom_list.append(d[0])
   except Exception as e:
     print(str(e))
     traceback.print_exc(file=sys.stdout)
   finally:
     if cursor is not None: cursor.close()
     if conn is not None: conn.close()
   return dom_list

def read_domains():
   dom_file = '/var/tmp/phish_out_1'
   dom_list = [line.strip() for line in open(dom_file, 'r')]
   return dom_list

def process_domains(res_list,lbl):
   global h_labels
   res_dict = {}

   res_conn = None
   res_cursor = None

   h_length = 19
   try:

     res_conn = connect_result()
     res_cursor = res_conn.cursor()

     res_obj = predict.load_model_dt()
     model = res_obj['model']
     pca = res_obj['pca']

     counter = 0

     for r in res_list:
         d = r["domain"]
         verification_time = r["verification_time"]
         if not (resolve_dns(d)): 
            continue
         else:
            pass

         print('----------------------------------------------------')
         print(print_date() + ' ' + d)

         check_res = check_url(d)
         #print(check_res)

         url = check_res['url']
         code = check_res['code']
         is_https = check_res['is_https']

         print(url)

         if code!=200: 
            continue

         try:
            save_site(d, url, predict_dir)
         except Exception as e:
            print(str(e))
            traceback.print_exc(file=sys.stdout)
            continue 

         html_path = predict_dir + '/' + d + '.html'
         img_path = predict_dir + '/' + d + '.png'

         if not (os.path.isfile(html_path) and os.path.isfile(img_path)):
             print("HTML/IMG path not exists  -- " + d)
             continue

         html_content = None
         try:
            with open(html_path) as file:
               html_content = file.read()
         except Exception as e:
             print(str(e))
             traceback.print_exc(file=sys.stdout)
         if html_content is None: 
             remove_site_files(d)
             continue

         #Skip pages that are irrelavant
         ###html_simhash_res = utils.extract_template_from_html(html_path)
         ###html_simhash = str(html_simhash_res)

         ##hash_chunks = split_hash(html_simhash, h_length)
         ###f_key_phrase = filter_by_key_phrases(html_path)
         f_key_phrase = feature_extract.filter_by_key_phrases(html_path)
         print("PHRASE: " + str(f_key_phrase) + ' -- ' + str(d))
         #if f_key_phrase: print(html_content)
         if f_key_phrase:  
             write_to_skipped_log("FILTER BY KEY PHRASE	" + lbl + "	" + f_key_phrase + "	" + d)
             remove_site_files(d)
             continue

         if feature_extract.filter_by_header(html_path):
             write_to_skipped_log("FILTER BY HEADER KEYS " + lbl + "    " + d)
             continue

         ###if hash_chunks[0] in simhashes_to_skip: 
         ###    write_to_skipped_log("FILTER BY SIMHASH	" + lbl + "	" +  d)
         ###    remove_site_files(d)
         ###    continue

         dt = datetime.now(tz).timestamp()
         dt_m = datetime.fromtimestamp(dt)

         vals = (dt_m, d, url, lbl, verification_time)
         query = 'INSERT IGNORE INTO predict_url_collection (detection_time, domain, url, lbl, verification_time) VALUES (%s,%s,%s,%s,%s)'

         res_cursor.execute(query, vals)
         if res_conn is not None: res_conn.commit()

   except Exception as e:
     print(str(e))
     traceback.print_exc(file=sys.stdout)
   finally:
     if res_cursor is not None: res_cursor.close()
     if res_conn is not None: res_conn.close()

def save_ocr_text(text, path):
   try:
      with open(path, 'w+') as f:
         f.write(text)
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def get_img_text_ocr(img_path):
    """
    :param img_path:
    :return:
    This part is to extract words from an image. We apply OCR technique to read texts from images.
    More info on OCR can be found:
    https://github.com/madmaze/pytesseract
    """
    text = ''
    try:
       img = Image.open(img_path)
       text = pytesseract.image_to_string(img, lang='eng')
    except Exception as e:
       print(str(e))
       traceback.print_exc(file=sys.stdout)
       if text == '': return ('','')

    #Filter phishing pages for unrelated content
    for ele in FILTER_KEYS:
       if text:
          if ele.lower() in text.lower():
              return ('','')
    sent = word_tokenize(text.lower())
    words = [word.lower() for word in sent if word.isalpha()]

    stop_words = set(stopwords.words('english'))
    words = [w for w in words if w not in stop_words]
    ocr_text = ' '.join(words)
    return (text,ocr_text)

def get_phishtank_domains():
   global threshold_days
   phishtank_file = '/var/tmp/phish'

   resp_json = None
   with open(phishtank_file) as json_file:
      resp_json = json.load(json_file)

   url_dict = {}

   out_file = '/var/tmp/phish_out'
   if os.path.exists(out_file): os.remove(out_file)

   counter = 0

   for j_obj in resp_json:
            #if counter > 10: break #REMOVE
            url_str = j_obj['url']
            verification_time = j_obj["verification_time"]
            verification_time = verification_time.replace('+00:00','')

            ver_utc_time = datetime.strptime(verification_time, "%Y-%m-%dT%H:%M:%S")

            ver_epoch_time = (ver_utc_time - datetime(1970, 1, 1)).total_seconds()

            re_skip_url = re.search('://(.+?)/.+', url_str)
            if re_skip_url: continue

            re_url = re.search('://(.+?)/', url_str)
            if (re_url):
               dom_str = re_url.group(1)
               if (dom_str):
                   tmp_dom_str = dom_str
                   tmp_dom_str = tmp_dom_str.replace('www.','')

                   whois_info_obj = feature_extract.extract_whois_info(tmp_dom_str)
                   if len(whois_info_obj) == 0: continue
                   if 'Creation Date' not in whois_info_obj: continue
                   dom_cr_date_str = whois_info_obj['Creation Date']
                   dom_cr_date_str_1 = ''
                   if dom_cr_date_str and len(dom_cr_date_str) > 0:
                      dom_cr_date_str_1 = dom_cr_date_str[0]
                      dom_cr_date_str_1 = dom_cr_date_str_1.replace('Z','')
                   dom_cr_date_epoch = 0
                   if dom_cr_date_str_1:
                       dt_re = re.search('(\d+?-\d+?-\d+?T\d+?:\d+?:\d+?)', dom_cr_date_str_1)
                       if dt_re:
                          dom_cr_date_str_1 = dt_re.group(1)
                       try:
                          dom_cr_date_epoch_utc = datetime.strptime(dom_cr_date_str_1, "%Y-%m-%dT%H:%M:%S")
                          dom_cr_date_epoch = (dom_cr_date_epoch_utc  - datetime(1970, 1, 1)).total_seconds()
                       except Exception as e:
                          try:
                             dom_cr_date_epoch_utc = datetime.strptime(dom_cr_date_str_1, "%Y-%m-%d %H:%M:%S")
                             dom_cr_date_epoch = (dom_cr_date_epoch_utc  - datetime(1970, 1, 1)).total_seconds()
                          except Exception as e:
                             #print(str(e))
                             pass

                   if dom_cr_date_epoch == 0: continue
                   delta_days = int(round(((ver_epoch_time-dom_cr_date_epoch)/(60*60*24)),1))

                   if delta_days <= threshold_days:
                      url_dict[url_str] = {'domain': dom_str, 'verification_time': verification_time}    
                      print(url_dict[url_str])
                      counter += 1

   return url_dict

def get_openphish_domains(dom_dict):
   global threshold_days
   phishtank_file = '/var/tmp/phish'

   url_dict = {}

   out_file = '/var/tmp/openphish_out'
   if os.path.exists(out_file): os.remove(out_file)

   counter = 0

   #time_day = datetime.now().timestamp()
   #date_day_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time_day))
   #ver_dt = datetime.strptime(date_day_str, '%Y-%m-%d %H:%M:%S')

   ver_epoch_time =  int(time.time())
   verification_time = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime())

   for dom_str in dom_dict:
            #if counter > 10: break #REMOVE
            url_str = dom_dict[dom_str]
            #verification_time = ver_dt

            #ver_utc_time = datetime.strptime(, "%Y-%m-%dT%H:%M:%S")
            #ver_epoch_time = (ver_utc_time - datetime(1970, 1, 1)).total_seconds()

            if (dom_str):
                   tmp_dom_str = dom_str
                   tmp_dom_str = tmp_dom_str.replace('www.','')

                   whois_info_obj = feature_extract.extract_whois_info(tmp_dom_str)
                   if len(whois_info_obj) == 0: continue
                   if 'Creation Date' not in whois_info_obj: continue
                   dom_cr_date_str = whois_info_obj['Creation Date']
                   dom_cr_date_str_1 = ''
                   if dom_cr_date_str and len(dom_cr_date_str) > 0:
                      dom_cr_date_str_1 = dom_cr_date_str[0]
                      dom_cr_date_str_1 = dom_cr_date_str_1.replace('Z','')
                   dom_cr_date_epoch = 0
                   if dom_cr_date_str_1:
                       dt_re = re.search('(\d+?-\d+?-\d+?T\d+?:\d+?:\d+?)', dom_cr_date_str_1)
                       if dt_re:
                          dom_cr_date_str_1 = dt_re.group(1)
                       try:
                          dom_cr_date_epoch_utc = datetime.strptime(dom_cr_date_str_1, "%Y-%m-%dT%H:%M:%S")
                          dom_cr_date_epoch = (dom_cr_date_epoch_utc  - datetime(1970, 1, 1)).total_seconds()
                       except Exception as e:
                          try:
                             dom_cr_date_epoch_utc = datetime.strptime(dom_cr_date_str_1, "%Y-%m-%d %H:%M:%S")
                             dom_cr_date_epoch = (dom_cr_date_epoch_utc  - datetime(1970, 1, 1)).total_seconds()
                          except Exception as e:
                             #print(str(e))
                             pass

                   if dom_cr_date_epoch == 0: continue
                   delta_days = int(round(((ver_epoch_time-dom_cr_date_epoch)/(60*60*24)),1))

                   if delta_days <= threshold_days:
                      url_dict[url_str] = {'domain': dom_str, 'verification_time': verification_time}
                      print(url_dict[url_str])
                      counter += 1

   return url_dict



def main():
   remove_file(skipped_sites_log)
   create_db()

   openphish_doms = blacklists.get_openphish_domains()
   #res_doms = get_openphish_domains(openphish_doms)
   #print(res_doms)

   #system.exit(0) #REMOVE

   blacklists.get_phishtank_domains()

   o_file = '/var/tmp/ph_new_doms'
   o_file_e = '/var/tmp/ph_new_doms_e'
   if os.path.exists(o_file): os.remove(o_file)
   if os.path.exists(o_file_e): os.remove(o_file_e)
   
   
   #Phishtank 
   ph_url_dict = get_phishtank_domains()
   print(ph_url_dict)

   for u in ph_url_dict:
      with open(o_file, 'a+') as the_file:
          the_file.write(ph_url_dict[u]['domain'] + ',' + ph_url_dict[u]['verification_time'] + '\n')

   for u in ph_url_dict:
      with open(o_file_e, 'a+') as the_file:
          the_file.write(ph_url_dict[u]['domain'] + '	' + 'phishing' + '	' + 'phishtank' +   '\n')

   #--------------------------------
   #Openphish
   openph_url_dict = get_openphish_domains(openphish_doms)
   print(openph_url_dict)

   for u in openph_url_dict:
      with open(o_file, 'a+') as the_file:
          the_file.write(openph_url_dict[u]['domain'] + ',' + openph_url_dict[u]['verification_time'] + '\n')

   for u in openph_url_dict:
      with open(o_file_e, 'a+') as the_file:
          the_file.write(openph_url_dict[u]['domain'] + '	' + 'phishing' + '	' + 'openphish' + '\n')

   #-------------------------------
   
   ph_list = []
   bn_doms = []
   file_p = open(o_file, "r") 
   for line in file_p: 
         line = line.strip()
         if not line: continue
         line_arr = line.split(',')
         ver_utc_time = datetime.strptime(line_arr[1], "%Y-%m-%dT%H:%M:%S")
         ph_list.append({'domain': line_arr[0], 'verification_time': ver_utc_time}) 

   ph_dom_size = len(ph_list)
   threshold_days = 7
   benign_chunk_size = int(round((ph_dom_size/threshold_days)*2.5,0))

   time_day = datetime.now().timestamp() - 2*60*60*24 
   date_day_str = time.strftime('%d%m%Y', time.localtime(time_day))
   ver_dt = datetime.strptime(date_day_str, '%d%m%Y')
   benign_dom_dict = {}

   for n in range(threshold_days-2):
        time_day = time_day - 1 * 60*60*24 
        print(date_day_str)
        benign_dom_dict[date_day_str] = get_new_domains_from_mysql(date_day_str, benign_chunk_size)
        #bn_doms.extend(benign_dom_dict[date_day_str])
        for dom in benign_dom_dict[date_day_str]:
           bn_doms.append({'domain': dom, 'verification_time': ver_dt})
        date_day_str = time.strftime('%d%m%Y', time.localtime(time_day))
        ver_dt = datetime.strptime(date_day_str, '%d%m%Y')
   random.shuffle(bn_doms)

   for d in bn_doms:
     with open(o_file, 'a+') as the_file:
          the_file.write(d['domain'] + '\n')

   for d in bn_doms:
     with open(o_file_e, 'a+') as the_file:
          the_file.write(d['domain'] + '	' + 'benign' +  '\n')

   print(len(ph_list))
   print(len(bn_doms))
   aggr_dom_list = ph_list + bn_doms
   random.shuffle(aggr_dom_list)

   process_domains(ph_list,'phishing')
   process_domains(bn_doms,'benign')

   

   
   #dlist = ['mygeniusglobal.com','new-control-pamis.com']
   #dlist = ['cbc.ca','nayanamana.com','bbc.com','amazon.com','ebay.com']
   #dlist = ['cbc.ca']
   #process_domains(dlist,'phishing')
   

   #url = 'http://lankapage.com'
   #domain = 'lankapage.com'
   #out_dir = '/tmp/nnn'
   
   #save_site(domain, url, out_dir)

    


### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

