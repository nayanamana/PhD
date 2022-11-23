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

from pytz import timezone
tz = timezone('EST')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
from heuristics import extract_heuristics

mysql_user = 'root'
mysql_pwd = 'mysql'
mysql_db = 'phishing_results_schema'

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_2/phishing_results_2.sql'

vt_api_key = VT_API_KEY

def create_db():
   global mysql_user
   global mysql_pwd
   global db_create_sql_file

   print("Creating database/tables (if not exist) - phishing_results_schema")

   cmd = '/usr/bin/mysql -u ' + mysql_user + ' -p' + mysql_pwd + ' < ' + db_create_sql_file
   print("Running command => " + cmd)
   output = subprocess.getoutput(cmd)
   print(output)
   print('--------------------------------------')

def connect_mal_result():
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
            print('Connected to MySQL database')
            return conn

    except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def submit_url_to_vt(url):
   command_str = "/usr/bin/curl -s --request POST --url https://www.virustotal.com/api/v3/urls --header 'x-apikey: " + vt_api_key + "' --form url='" + url + "'"
   output = subprocess.getoutput(command_str)
   #print(output)

   id_str = ""
   try:
      output_obj = json.loads(output)
      if "data" in output_obj and "id" in output_obj["data"]:
         id_str = output_obj["data"]["id"]
   except Exception as e:
        pass

   return id_str 

def analyze_url_from_vt(id_str):
   command_str = "/usr/bin/curl -s --request GET --url https://www.virustotal.com/api/v3/analyses/" + id_str + " --header 'x-apikey: " + vt_api_key + "'" 
   output = subprocess.getoutput(command_str)

   return output



def check_url(dom):
   #dom = 'lankapage.com'
   url = 'https://' + dom
   is_https = 0
   code = 999
   '''
   try:
       url = 'https://' + dom
       response = requests.head(url, verify=False, timeout=1)

       if int(str(response.status_code)[:1]) < 4: #if the url is up, the status code should not be 4xx or 5xxx
          is_https = 1
          code = response.status_code
   except Exception as e:
       print(str(e))
       pass
   '''
   try:
      url = 'https://' + dom
      session = HTMLSession(verify=False)
      r = session.get(url,timeout=2)
      #if r.status_code == 200:
      if int(str(r.status_code)[:1]) < 4:
         is_https = 1
         code = r.status_code
   except Exception as e:
      print(str(e))
      pass

   '''
   if is_https == 0:
       try:
          url = 'http://' + dom
          response = requests.head(url, verify=False, timeout=1)

          is_https = 0
          code = response.status_code
       except Exception as e:
          #print(str(e))
          pass
   '''
   if is_https == 0:
      try:
         url = 'http://' + dom
         session = HTMLSession(verify=False)
         r = session.get(url,timeout=2)
         is_https = 0
         code = r.status_code
      except Exception as e:
         #print(str(e))
         pass


   return {'is_https': is_https, 'code': code}


def get_spamhaus_mal_type(code):
   #Ref: https://www.spamhaus.org/faq/section/Spamhaus%20DBL
   if code == '127.0.1.2':
      return 'spam'
   if code == '127.0.1.4':
      return 'phish'
   if code == '127.0.1.5':
      return 'malware'
   if code == '127.0.1.6':
      return 'botnet C&C'
   if code == '127.0.1.102':
      return 'abused legit spam'
   if code == '127.0.1.103':
      return 'abused spammed redirector domain'
   if code == '127.0.1.104':
      return 'abused legit phish'
   if code == '127.0.1.105':
      return 'abused legit malware'
   if code == '127.0.1.106':
      return 'abused legit botnet C&C'
   if code == '127.0.1.255':
      return 'IP queries prohibited'
   return ""

def get_surbl_mal_type(code):
   #Ref: http://www.surbl.org/lists
   if code.endswith('8'):
      return 'phish'
   if code.endswith('16'):
      return 'malware'
   if code.endswith('64'):
      return 'abuse'
   if code.endswith('128'):
      return 'cracked'
   if code.endswith('22'):
      return 'phish,malware'
   if code.endswith('72'):
      return 'phish,abuse'
   if code.endswith('136'):
      return 'phish,cracked'
   if code.endswith('80'):
      return 'malware,abuse'
   if code.endswith('144'):
      return 'malware,cracked'
   if code.endswith('192'):
      return 'abuse,cracked'
   if code.endswith('88'):
      return 'phish,malware,abuse'
   if code.endswith('208'):
      return 'malware,abused,cracked'
   if code.endswith('152'):
      return 'phish,malware,cracked'
   if code.endswith('200'):
      return 'phish,abuse,cracked'
   if code.endswith('216'):
      return 'phish,malware,abuse,cracked'

def insert_heuristics(dom_obj, new_dom_table, mal_type):
   conn = connect_mal_result()
   cursor = conn.cursor()

   domain = dom_obj['domain']
   cert = dom_obj['cert']

   create_db()
   heuristics_obj = extract_heuristics(domain,cert)
   heuristics_json = json.dumps(heuristics_obj)

   time_today = datetime.now(tz).timestamp()
   date_today = time.strftime('%d%m%Y', time.localtime(time_today))

   try:
      vals = (domain, new_dom_table, 1, heuristics_json, mal_type)
      query = 'INSERT IGNORE INTO heuristics_ph_' + str(date_today) + ' (domain,new_dom_table,is_mal,heuristics,mal_type) VALUES (%s,%s,%s,%s,%s);'
      cursor.execute(query, vals)
      conn.commit()
   except Exception as e:
      print(str(e))

def check_domain_with_spamhaus(domain):
    cmd_str = '/usr/bin/host ' + domain + '.dbl.spamhaus.org'
    output = subprocess.getoutput(cmd_str)

    result = {}

    if 'NXDOMAIN' in output: return result
    re_spam = re.match('(.+?)\.dbl\.spamhaus\.org has address (.+)', output)
    if (re_spam):
        s_domain = re_spam.group(1)
        s_code = re_spam.group(2)
        s_mal_type = get_spamhaus_mal_type(s_code) if s_code else ""
        result = {'domain': s_domain, 'code': s_code, 'mal_type': s_mal_type}
    return result

def get_spamhaus_domains(dom_list,new_dom_table):
   conn = connect_mal_result()
   cursor = conn.cursor()

   print("Finding malicious domains from spamhaus...")

   for dom_obj in dom_list:
      s_dom = dom_obj['domain']

      cmd_str = '/usr/bin/host ' + s_dom[0] + '.dbl.spamhaus.org'
      output = subprocess.getoutput(cmd_str)
      #output = 'cpcontacts.sallykaye.com.dbl.spamhaus.org has address 127.0.1.2'
      utc_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

      #print(output, flush=True)
      if 'NXDOMAIN' in output: continue
      re_spam = re.match('(.+?)\.dbl\.spamhaus\.org has address (.+)', output)
      if (re_spam):
          s_domain = re_spam.group(1)
          s_code = re_spam.group(2)
          s_mal_type = get_spamhaus_mal_type(s_code) if s_code else ""
          #print(utc_date + ' -- ' + s_domain + ' -- ' + str(s_code) + ' -- ' + s_mal_type)

          domain_status = json.dumps(check_url(s_domain))
          vals = (utc_date, s_domain, s_code, s_mal_type, 'spamhaus',new_dom_table,domain_status)
          query = 'INSERT IGNORE INTO mal_domains (detection_time,domain,result,mal_type,source,new_dom_table,status) VALUES (%s,%s,%s,%s,%s,%s,%s);'
          print(query)
          print(vals)
          print('-------------------------------------')
          cursor.execute(query, vals)
          conn.commit()

          if 'phish' in s_mal_type:
             insert_heuristics(dom_obj, new_dom_table, s_mal_type) 

def get_surbl_domains(dom_list,new_dom_table):
   conn = connect_mal_result()
   cursor = conn.cursor()

   print("Finding malicious domains from surbl...")

   for dom_obj in dom_list:
      s_dom = dom_obj['domain']

      cmd_str = '/usr/bin/host ' + s_dom[0] + '.multi.surbl.org'
      output = subprocess.getoutput(cmd_str)
      utc_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

      if 'NXDOMAIN' in output: continue
      re_spam = re.match('(.+?)\.multi\.surbl\.org has address (.+)', output)
      if (re_spam):
          s_domain = re_spam.group(1)
          s_code = re_spam.group(2)
          s_mal_type = get_surbl_mal_type(s_code) if s_code else ""

          domain_status = json.dumps(check_url(s_domain))
          vals = (utc_date, s_domain, s_code, s_mal_type, 'surbl',new_dom_table,domain_status)
          query = 'INSERT IGNORE INTO mal_domains (detection_time,domain,result,mal_type,source,new_dom_table,status) VALUES (%s,%s,%s,%s,%s,%s,%s);'
          print(query)
          print(vals)
          print('-------------------------------------')
          cursor.execute(query, vals)
          conn.commit()

          if 'phish' in s_mal_type:
             insert_heuristics(dom_obj, new_dom_table, s_mal_type)

def get_phishtank_domains(dom_list,new_dom_table):
   print("Finding malicious domains from phishtank.....")
   key = '5f9311572449d07b87b8aff82548dcacc9e4b1dbe0d8b5829b34f4ec125dd8e9'
   url = 'http://data.phishtank.com/data/' + key + '/online-valid.json'

   url_dict  = {}

   conn = connect_mal_result()
   cursor = conn.cursor()

   print("Finding malicious domains from PhishTank...")

   try:
         '''
         response = requests.get(url)
         if response.status_code != 200:
             print(url + " returned non-200 status code")
             print(response)
             return
         resp_json = response.json()

         with open('/var/tmp/phish', 'w+', encoding='utf-8') as f:
             json.dump(resp_json, f, ensure_ascii=False, indent=4)
         '''
         
         resp_json = None
         with open('/var/tmp/phish') as json_file:
             resp_json = json.load(json_file)

         for j_obj in resp_json:
            url_str = j_obj['url']
            re_url = re.search('://(.+?)/', url_str)
            #print(re_url + ' -- ' + url_str)
            if (re_url):
               dom_str = re_url.group(1)
               if (dom_str):
                  url_dict[dom_str] = j_obj

         for dom_obj in dom_list:
                     s_dom = dom_obj['domain']

                     if s_dom not in url_dict: continue
                     utc_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                     #s_dom_t = 'http://' + s_dom[0]
                     try:
                         domain_status = json.dumps(check_url(s_dom))
                         vals = (utc_date, s_dom, json.dumps(url_dict[s_dom]), 'phish', 'phishtank',new_dom_table,domain_status)
                         query = 'INSERT IGNORE INTO mal_domains (detection_time,domain,result,mal_type,source,new_dom_table,status) VALUES (%s,%s,%s,%s,%s,%s,%s);'
                         print(query)
                         print(vals)
                         print('---------------------------------------------')
                         cursor.execute(query, vals)
                         conn.commit()
                     except ValueError as e:
                         print(str(e))
                         traceback.print_exc(file=sys.stdout)
                     except Exception as ex:
                         print("Error detected: " + str(ex))
                         traceback.print_exc(file=sys.stdout)

                     insert_heuristics(dom_obj, new_dom_table, 'phish')

   except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)

