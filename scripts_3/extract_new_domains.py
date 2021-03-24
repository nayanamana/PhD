#!/usr/bin/python3.7

import warnings
warnings.filterwarnings('ignore')

import sys, os, json
from requests_html import HTMLSession

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import subprocess
import traceback
from datetime import datetime
import time
from datetime import timezone
import re
import requests as reqs

import csv
import glob

import mysql.connector
from mysql.connector import Error

from collections import OrderedDict
import base64
import io
import zipfile

import requests
#Ref: https://code-maven.com/python-timeout
import signal
#Ref: https://stackoverflow.com/questions/19080792/run-separate-processes-in-parallel-python
from multiprocessing import Pool

from pytz import timezone
tz = timezone('EST')

pghost = "crt.sh"
db = "certwatch"
postgres_user = "guest"

mysql_user = 'root'
mysql_pwd = 'mysql'
batch_size = 100000

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_2/create_db_2.sql'


class TimeOutException(Exception):
   pass

def alarm_handler(signum, frame):
   raise TimeOutException()

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

def connect():
    """ Connect to MySQL database """
    print("Connecting to mysql database (phishing_schema)...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            print('Connected to MySQL database - phishing_schema')
            return conn

    except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def check_url(dom):
   #dom = 'lankapage.com'
   url = 'https://' + dom
   is_https = 0
   code = 999
   '''
   try:
       url = 'https://' + dom
       signal.signal(signal.SIGALRM, alarm_handler)
       signal.alarm(3) #alarm after 3 seconds
       response = requests.head(url, verify=False, timeout=1)

       if int(str(response.status_code)[:1]) < 4: #if the url is up, the status code should not be 4xx or 5xxx
          is_https = 1
          code = response.status_code
   except Exception as e:
       print(str(e))
       pass
   finally:
       signal.alarm(0) #reset alarm

   if is_https == 0:
       try:
          url = 'http://' + dom
          signal.signal(signal.SIGALRM, alarm_handler)
          signal.alarm(3) #alarm after 3 seconds
          response = requests.head(url, verify=False, timeout=1)

          is_https = 0 
          code = response.status_code
       except Exception as e:
          #print(str(e))
          pass
       finally:
         signal.alarm(0) #reset alarm
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

def extract_domain_cert(dom):
   global pghost
   global db
   global postgres_user

   #print("Extracting domain certificate for domain: " + dom)

   query = "SELECT row_to_json(u) FROM (SELECT certificate_id, issuer_ca_id, x509_commonName(certificate) as common_name, x509_issuerName(certificate) as issuer_name, x509_notBefore(certificate) as not_before, x509_notAfter(certificate) as not_after, x509_keyAlgorithm(certificate) as key_algorithm, x509_keySize(certificate) as key_size, x509_serialNumber(certificate) as serial_number, x509_signatureHashAlgorithm(certificate) as signature_hash_algorithm, x509_signatureKeyAlgorithm(certificate) as signature_key_algorithm, x509_subjectName(certificate) as subject_name, x509_name(certificate) as name, x509_altNames(certificate) as alt_names FROM (SELECT certificate_id, certificate, issuer_ca_id FROM certificate_and_identities cai WHERE plainto_tsquery('certwatch', '" + dom + "') @@ identities(cai.CERTIFICATE) AND cai.NAME_VALUE ILIKE ('" + dom + "') AND cai.name_type='san:dNSName' LIMIT 10000) n order by n.certificate_id DESC LIMIT 1) u;"

   cmd = '/usr/bin/psql -t -h ' + pghost + ' -p 5432 -U ' + postgres_user + ' -d ' + db + ' -c "' + query + '"'
   #print("Running command => " + cmd)
   output = subprocess.getoutput(cmd)
   time.sleep(1)
   #print(output)
   return output

def extract_domain_certs(dom_list):
   conn = None
   cursor = None
   try:
     #connect to mysql database
     conn = connect()
     cursor = conn.cursor()

     row_count = 0
     batch_count = 100

     for d in dom_list:
       row_count += 1
       d_cert = extract_domain_cert(d)

       #yesterday_date = datetime.utcnow().strftime("%d%m%Y")
       time_yesterday = datetime.now(tz).timestamp() - 60*60*24 #REMOVE
       #print(time_yesterday)
       date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday))

       vals = (d, d_cert)
       query = 'INSERT IGNORE INTO new_doms_' + str(date_yesterday) + ' (domain, cert) VALUES (%s,%s)'
       cursor.execute(query, vals)

       if row_count % batch_count == 0:
           #print("Commiting " + str(batch_count) + " to table: certificate [INSERTED COUNT: " + str(row_count) + " ...")
           #print(str(row_count))
           conn.commit()
     conn.commit()
     time_yesterday = datetime.now(tz).timestamp() - 60*60*24 #REMOVE
     date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday))
     print("Finished inserting records to new_doms_" + str(date_yesterday) + " table [END TIME: " + print_datetime() + "]")
   except Exception as e:
     print(str(e))
     traceback.print_exc(file=sys.stdout)
   finally:
     if conn is not None: conn.commit()
     if cursor is not None: cursor.close()
     if conn is not None: conn.close()

def print_datetime():
   now = datetime.now(tz)
   dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
   print("Time now =", dt_string)
   return str(dt_string)

def chunks(l, n):
    """Yield n number of striped chunks from l."""
    for i in range(0, n):
        yield l[i::n]
    return l

def download_newly_registered_domains():
   #Ref: https://isc.sans.edu/forums/diary/Tracking+Newly+Registered+Domains/23127/
   time_yesterday = datetime.now(tz).timestamp() - 1*60*60*24
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
   download_file = download_path + '/' + 'new_doms_' + date_yesterday_zip
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
   chunk_list_gen = chunks(dom_list, 5)

   chunk_list_sub = []

   for item in chunk_list_gen:
      chunk_list_sub.append(item)

   pool = Pool(processes=5)
   result0 = pool.apply_async(extract_domain_certs, [chunk_list_sub[0]])
   result1 = pool.apply_async(extract_domain_certs, [chunk_list_sub[1]])
   result2 = pool.apply_async(extract_domain_certs, [chunk_list_sub[2]])
   result3 = pool.apply_async(extract_domain_certs, [chunk_list_sub[3]])
   result4 = pool.apply_async(extract_domain_certs, [chunk_list_sub[4]])
   #print(result0)
   pool.close()
   pool.join()
   time.sleep(3)

   #Remove zipped file
   if os.path.exists(download_file): os.remove(download_file) #REMOVE
   




def main():
    #create database/tables (if not exists)
    create_db()
    download_newly_registered_domains()


### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

