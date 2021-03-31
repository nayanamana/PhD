#!/usr/local/bin/python3.8

import os, sys, json
import requests
import tldextract

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/1-Squatting-Domain-Identification')

import utils
import squatting_type
import squatting_scan

import mysql.connector
from mysql.connector import Error
import traceback
import datetime
from datetime import timezone
from datetime import datetime,timedelta
import time

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

def get_top_isitphishing_targets(top_num):
   result = []
   result_int = {}
   blacklist = ['line', 'free', 'oney', 'post', 'match', 'discover', 'sella', 'battle', 'poste']
   url = 'https://isitphishing.ai/request.php?str=getbrands'
   headers = {
      "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
      "Content-Type": 'application/json; charset=utf-8',
      "Referer": 'https://isitphishing.ai/phishing-directory'
   }
   payload = {}
   #r = requests.post(url, data=json.dumps(payload), headers=headers)
   r = requests.post(url, data=payload, headers=headers)
   json_obj = json.loads(r.content)
   if "brands" not in json_obj:
      return {}
   else:
       json_obj = json_obj["brands"]
       for item in json_obj:
          bl_skip = 0
          for bl in blacklist:
            if bl in item['website']:
               bl_skip = 1
               break 
          if bl_skip == 0:
               result_int[item['website']] = item['urls']
   
   no_of_urls_list = list(result_int.values())
   no_of_urls_list.sort(reverse=True)
   no_of_urls_list = no_of_urls_list[:top_num]

   counter = 0
   for url in result_int:
      val = result_int[url]
      if val in no_of_urls_list:
         ext = tldextract.extract(url)
         tld_plus_one = ext.domain
         if len(tld_plus_one) < 4: continue
         result.append(tld_plus_one)
         counter += 1
         if counter > top_num: break

   return result

def get_new_domains_from_mysql(date_str, isitphishing_threshold):

   res_list = []

   isit_phish = get_top_isitphishing_targets(isitphishing_threshold)
   #print(isit_phish)
   #print(len(isit_phish))
   #return #REMOVE
   #is_it_phish_str = '|'.join(isit_phish)

   #sql = "SELECT domain from new_doms_" + date_str  + " where domain regexp '" + is_it_phish_str  + "' order by rand()"# #REMOVE

   dom_found = {}

   #Top brands
   for dom in isit_phish:
      sql = "SELECT domain from new_doms_" + date_str  + " where domain like '%" + dom  + "%' order by rand()"# #REMOV
      print(sql)

      conn = None
      cursor = None

      try:
        #connect to mysql database
        conn = connect_source()
        cursor = conn.cursor()

        #print("Getting new domains from table: 'new_doms' for date: '" + str(date_str) + "'")
        cursor.execute(sql)
        result_set = cursor.fetchall()

        counter = 0
        for d in result_set:
           d_str = 'http://' + d[0]
           print(d_str)
           if d_str not in dom_found:
              dom_found[d_str] = 1
              res_list.append(d_str)
      except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
      finally:
         cursor.close()
         conn.close()

   #Top sensitive keywords + homographs
   sensitive_keywords = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm","update","security","login","billing"]
   for s_kw in sensitive_keywords:
      sql = "SELECT domain from new_doms_" + date_str  + " where domain like '%" + s_kw  + "%' or domain like 'xn--%' order by rand()"# #REMOV
      print(sql)

      conn = None
      cursor = None

      try:
        #connect to mysql database
        conn = connect_source()
        cursor = conn.cursor()

        #print("Getting new domains from table: 'new_doms' for date: '" + str(date_str) + "'")
        cursor.execute(sql)
        result_set = cursor.fetchall()

        counter = 0
        for d in result_set:
           d_str = 'http://' + d[0]
           print(d_str)
           if d_str not in dom_found:
              dom_found[d_str] = 1
              res_list.append(d_str)
      except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
      finally:
         cursor.close()
         conn.close()

   
   #Check typo-squatting domains using SquatPhish
   try:
      sql =  "SELECT domain from new_doms_" + date_str #+ " limit 1000" #REMOVE limit
      conn = connect_source()
      cursor = conn.cursor() 

      cursor.execute(sql)
      result_set = cursor.fetchall()

      for d in result_set:
           d_str = d[0]
           if d_str not in dom_found:
              type_obj = squatting_scan.get_type(d_str)
              if len(type_obj) > 0:
                 dom_found[d_str] = 1
                 u = 'http://' + d_str
                 res_list.append(u)
   except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)
   finally:
         cursor.close()
         conn.close()
  

   return res_list

def write_to_out_file(date_yesterday, filtered_doms, date_yesterday_file):
   out_file = '/mnt/extra1/projects/phishing/scripts_m3/url_lists/list_' + str(date_yesterday_file) 
   with open(out_file, 'w+') as f:
      for d in filtered_doms:
         f.write(d + '\n')


def main():
   #isit_phish = get_top_isitphishing_targets(100)
   #print(isit_phish)
   time_yesterday = datetime.now().timestamp() - 2*60*60*24  #* 2 #remove *2
   date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday)) #time.localtime(utcnow_str))
   date_yesterday_file = time.strftime('%d%m%y', time.localtime(time_yesterday))
   isitphishing_threshold = 500
   #isitphishing_threshold = 350
   #isitphishing_threshold = 1500

   filtered_doms = get_new_domains_from_mysql(date_yesterday, isitphishing_threshold)
   #print(filtered_doms)
   write_to_out_file(date_yesterday, filtered_doms, date_yesterday_file)

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()



