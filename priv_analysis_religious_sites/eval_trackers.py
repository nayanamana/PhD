#!/home/naya/miniconda3/bin/python3

import json, re, sys, os 
import sqlite3
from sqlite3 import Error

sys.path.append('/mnt/extra1/projects/religious_sites/scripts')

from urllib.parse import urlparse
from publicsuffix2 import PublicSuffixList

#from publicsuffix2 import fetch

import BlockListParser
from BlockListParser import BlockListParser
from DBAdapter import DBAdpater
from blp_utils import is_js, is_image, get_option_dict
import pandas as pd
import csv
import tldextract
import leveldb

#from ip2geotools.databases.noncommercial import DbIpCity
#from geoip import open_database
from geoip import geolite2

from datetime import datetime
from dateutil import parser

#psl_file = fetch()
psl = PublicSuffixList()
#psl = PublicSuffixList(psl_file)

url_to_tld = {}
trk_dict = {}
adv_dict = {}
tp_to_tld = {}
ip_to_loc = {}

#geolite_db_file = '/mnt/extra1/projects/religious_sites/geolite/GeoLite2-Country_20220503/GeoLite2-Country.mmdb'
#geolite_db = open_database(geolite_db_file)

#with open_database(geolite_db_file) as db:
#    match = db.lookup_mine()
#    print('My IP info:', match)


filter_list_el = '/mnt/extra1/projects/religious_sites/filter_lists/easylist.txt'
filter_list_ep = '/mnt/extra1/projects/religious_sites/filter_lists/easyprivacy.txt'
#filter_list_el = '/mnt/extra1/projects/religious_sites/filter_lists1/Easylist.txt'
#filter_list_ep = '/mnt/extra1/projects/religious_sites/filter_lists1/EasyPrivacy.txt'

blocklist_parser_el = BlockListParser(filter_list_el)
blocklist_parser_ep = BlockListParser(filter_list_ep)
#print(blocklist_parser)

psl = PublicSuffixList()

def get_ck_validity_period(exp_date):
   cur_date_str = '2022-04-23T00:00:01'
   #Ref: https://stackoverflow.com/questions/54662514/how-to-get-expiry-date-from-cookies
   exp_dt = parser.parse(exp_date)
   exp_dt = exp_dt.replace(tzinfo=None)
   cur_dt = parser.parse(cur_date_str)
   cur_dt = cur_dt.replace(tzinfo=None)
   #print(exp_dt)
   #print(cur_dt)
   difference = exp_dt - cur_dt
   return difference.days

def get_2ld(url):
   ext = tldextract.extract(url)
   return ext.registered_domain

def is_tracker(fp_url, tp_url):
   global ps1
   global blocklist_parser_ep
   options = get_option_dict(tp_url, fp_url,
                                  True, False, psl)
   res = blocklist_parser_ep.should_block(tp_url, options)
   return res

def is_adv(fp_url, tp_url):
   global ps1
   global blocklist_parser_el
   options = get_option_dict(tp_url, fp_url,
                                  True, False, psl)
   res = blocklist_parser_el.should_block(tp_url, options)
   return res

#Ref: https://www.sqlitetutorial.net/sqlite-python/sqlite-python-select/
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)

    return conn

#Ref: https://stackoverflow.com/questions/3300464/how-can-i-get-dict-from-sqlite-query
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def write_output_to_csv(data_list, out_file):
   data_file = open(out_file, "w+", newline='\n', encoding='utf-8')
   csv_writer = csv.writer(data_file, lineterminator='\n')

   count = 0
   for item in data_list:
       if count == 0: 
          header = item.keys()
          csv_writer.writerow(header)
          count += 1

       csv_writer.writerow(item.values())
   data_file.close()

def select_all_site_visits(conn, out_dir, dir_key):
    global url_to_tld
    global trk_dict
    global adv_dict
    global tp_to_tld

    print("Running select_all_site_visits..")

    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("select distinct site_url from site_visits;")

    rows = cur.fetchall()

    outlist = []

    for row in rows:
        site_url = row['site_url']
        site_domain = get_2ld(site_url)
        #print(row)
        #print(site_domain)
        outlist.append({'site_url': site_url, 'site_domain': site_domain})

    #json_list = json.dumps(outlist)
    outdir_csv = out_dir + "/" + dir_key + "_site_visits_out.csv"

    write_output_to_csv(outlist, outdir_csv)

def select_all_js(conn, out_dir, dir_key):
    global url_to_tld
    global trk_dict
    global adv_dict
    global tp_to_tld

    print("Running select_all_js...")

    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("select distinct top_level_url, script_url from javascript;")

    rows = cur.fetchall()

    outlist = []

    for row in rows:
        #print(row)
        top_level_url = row['top_level_url']
        top_level_domain = get_2ld(top_level_url) if top_level_url not in url_to_tld else url_to_tld[top_level_url]

        script_url = row['script_url']
        script_url = script_url.replace('www.', '')

        surl_re = re.search('(.+?\.js)', script_url)
        if surl_re:
            script_url = surl_re.group(1)

         
        script_domain = get_2ld(script_url) if script_url not in tp_to_tld else tp_to_tld[script_url]
        if top_level_domain and script_domain and top_level_domain == script_domain: continue

        is_trk = is_tracker(top_level_url, script_url)
        is_advertiser = is_adv(top_level_url, script_url)
        trk_status = "-"
        if is_trk == True:
           trk_status = "TRACKER"
        if is_advertiser == True:
           trk_status = "ADVERTISER"

        outlist.append({'top_level_url': top_level_url, 'script_url': script_url, 'top_level_domain': top_level_domain, 'script_domain': script_domain, 'trk_status': trk_status})

    outdir_csv = out_dir + "/" + dir_key + "_js_out.csv"

    print(outdir_csv)
    write_output_to_csv(outlist, outdir_csv)

def select_all_js_cookies(conn, out_dir, dir_key):
    global url_to_tld
    global trk_dict
    global adv_dict
    global tp_to_tld

    print("Running select_all_js_cookies...")

    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("select distinct a.site_url, b.host, b.expiry, b.name, b.value, b.path, b.is_http_only, b.is_secure from site_visits a, javascript_cookies b where a.visit_id = b.visit_id and b.is_session = 0;")

    rows = cur.fetchall()

    outlist = []

    for row in rows:
        #print(row)
        top_level_url = row['site_url']
        top_level_domain = get_2ld(top_level_url) if top_level_url not in url_to_tld else url_to_tld[top_level_url]

        script_url = row['host']
        if script_url.startswith('.'):
            script_url = script_url[1:]
        script_url = script_url.replace('www.', '')

        surl_re = re.search('(.+?\.js)', script_url)
        if surl_re:
            script_url = surl_re.group(1)

        script_domain = get_2ld(script_url) if script_url not in tp_to_tld else tp_to_tld[script_url]
        if top_level_domain and script_domain and top_level_domain == script_domain: continue

        #is_trk = is_tracker(top_level_url, 'http://' + script_domain)
        #is_advertiser = is_adv(top_level_url, 'http://'  +script_domain)
        is_trk = is_tracker(top_level_url, 'http://' + script_url)
        is_advertiser = is_adv(top_level_url, 'http://'  +script_url)

        trk_status = "-"
        if is_trk == True:
           trk_status = "TRACKER"
        if is_advertiser == True:
           trk_status = "ADVERTISER"

        expiry = row['expiry']
        name = row['name']
        value = row['value']
        path = row['path']
        is_http_only = row['is_http_only']
        is_secure = row['is_secure']

        validity_period = get_ck_validity_period(expiry)
        #print(validity_period)

        outlist.append({'top_level_url': top_level_url, 'script_url': script_url, 'top_level_domain': top_level_domain, 'script_domain': script_domain, 'trk_status': trk_status,
           'expiry': expiry, 'name': name, 'value': value, 'path': path, 'is_http_only': is_http_only, 'is_secure': is_secure, 'validity_period': validity_period
           })

    outdir_csv = out_dir + "/" + dir_key + "_js_cookies_out.csv"

    write_output_to_csv(outlist, outdir_csv)


def select_all_fp(conn, out_dir, dir_key):
    global url_to_tld
    global trk_dict
    global adv_dict
    global tp_to_tld

    print("Running select_all_fp...")

    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("select distinct top_level_url,script_url, symbol from javascript ;")

    rows = cur.fetchall()

    outlist = []

    for row in rows:
        #print(row)
        top_level_url = row['top_level_url']
        top_level_domain = get_2ld(top_level_url) if top_level_url not in url_to_tld else url_to_tld[top_level_url]

        script_url = row['script_url']
        script_domain = get_2ld(script_url) if script_url not in tp_to_tld else tp_to_tld[script_url]
        if top_level_domain and script_domain and top_level_domain == script_domain: continue

        is_trk = is_tracker(top_level_url, 'http://' + script_domain)
        is_advertiser = is_adv(top_level_url, 'http://'  +script_domain)
        trk_status = "-"
        if is_trk == True:
           trk_status = "TRACKER"
        if is_advertiser == True:
           trk_status = "ADVERTISER"

        symbol = row['symbol']

        outlist.append({'top_level_url': top_level_url, 'script_url': script_url, 'top_level_domain': top_level_domain, 'script_domain': script_domain, 'trk_status': trk_status,
           'symbol': symbol
           })

    outdir_csv = out_dir + "/" + dir_key + "_fp_out.csv"

    write_output_to_csv(outlist, outdir_csv)

def select_all_geoip_info(conn, out_dir, dir_key):
    global url_to_tld
    global trk_dict
    global adv_dict
    global tp_to_tld
    global ip_to_loc
    global geolite_db

    print("Running select_all_geoip_info...")

    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("select distinct  s.site_url, d.used_address from site_visits s, dns_responses d where d.visit_id=s.visit_id and (s.site_url = 'https://' || d.hostname or s.site_url = 'http://' || d.hostname);")

    rows = cur.fetchall()

    outlist = []

    for row in rows:
        top_level_url = row['site_url']
        ip = row['used_address']

        loc = ""
        if ip not in ip_to_loc: 
            try:
               #response = DbIpCity.get(ip, api_key='free')
               #ip_to_loc[ip] = response.country
               #geo_obj = geolite_db.lookup(ip)
               #print(geo_obj)
               geodb_obj = geolite2.lookup(ip)
               #print(geodb_obj)
               if geodb_obj.location:
                  #print(geodb_obj)
                  loc = geodb_obj.country
            except Exception as e:
               pass
        else:
           loc = ip_to_loc[ip]

        outlist.append({'top_level_url': top_level_url, 'ip': ip, 'loc': loc
           })

    outdir_csv = out_dir + "/" + dir_key + "_geoip_out.csv"

    write_output_to_csv(outlist, outdir_csv)

def save_site_content(conn, content_ldb, out_dir, dir_key):
    global url_to_tld
    global trk_dict
    global adv_dict
    global tp_to_tld
    global ip_to_loc
    global geolite_db

    full_path = out_dir + "/" + dir_key
    if not os.path.exists(full_path):
       os.makedirs(full_path)

    print("Running save_site_content...")

    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("select h.url, s.site_url, h.content_hash from http_responses h, site_visits s where s.visit_id=h.visit_id and replace(replace(s.site_url,'/',''), 'https', 'http') = replace(replace(h.url, '/',''), 'https', 'http') ;")

    rows = cur.fetchall()

    outlist = []

    for row in rows:
        top_level_url = row['site_url']
        content_hash = row['content_hash']

        domain_name = ""
        re_url = re.search('://(.+)', top_level_url)
        if re_url:
            domain_name = re_url.group(1)
        else:
            continue

        if content_hash is None: continue
        response_content = ""
        try:
           response_content = content_ldb.Get(content_hash.encode('utf-8'))
        except Exception as e:
           continue

        try:
            response_content = response_content.decode('utf-8')
        except Exception as e:
            pass

        #write response content to file
        try:
            with open(full_path + "/" + domain_name + ".txt", "w+") as rep_cont_fl:
               #print(full_path + "/" + domain_name + ".txt")
               rep_cont_fl.write(response_content)
        except Exception as e:
            #print(str(e))
            pass



def eval_trk(sqlite_db, content_ldb, out_dir, dir_key):
   conn = create_connection(sqlite_db)
   select_all_site_visits(conn, out_dir, dir_key)
   select_all_js(conn, out_dir, dir_key)
   select_all_js_cookies(conn, out_dir, dir_key)
   select_all_fp(conn, out_dir, dir_key)
   select_all_geoip_info(conn, out_dir, dir_key)
   save_site_content(conn, content_ldb, out_dir, dir_key + "_content") #REMOVE


### MAIN ###
def main():
   out_dir = '/mnt/extra1/projects/religious_sites/out/'

   #sqlite_db = '/home/naya/install/OpenWPM/datadir/mega-churches-crawl-data.sqlite'
   #dir_key = 'megachurches'
   #eval_trk(sqlite_db, out_dir, dir_key)

   #sqlite_db = '/home/naya/install/OpenWPM/datadir/mosques-us-crawl-data.sqlite'
   #dir_key = 'mosque'
   
   #eval_trk(sqlite_db, out_dir, dir_key)

   #sqlite_db = '/home/naya/install/OpenWPM/datadir/hindu-temples-crawl-data.sqlite'
   #dir_key = 'hindu-temples'

   #eval_trk(sqlite_db, out_dir, dir_key)

   #sqlite_db = '/mnt/extra1/projects/religious_sites/openwpm_data/dataset1/religious-sites-crawl-data1.sqlite'
   sqlite_db = '/mnt/extra1/projects/religious_sites/openwpm_data/dataset2/religious-sites-crawl-data2.sqlite'
   #sqlite_db = '/home/naya/install/OpenWPM/datadir/canada-govt-sites-crawl-data.sqlite'

   #content_ldb_path = '/mnt/extra1/projects/religious_sites/openwpm_data/dataset1/content.ldb'
   content_ldb_path = '/mnt/extra1/projects/religious_sites/openwpm_data/dataset2/content.ldb'
   #content_ldb_path = '/home/naya/install/OpenWPM/leveldb/content.ldb'
   content_ldb = leveldb.LevelDB(content_ldb_path)
   dir_key = 'religious_sites'
   eval_trk(sqlite_db, content_ldb, out_dir, dir_key)


if __name__ == '__main__':
    main()


