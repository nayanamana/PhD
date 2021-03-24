import warnings
warnings.filterwarnings('ignore')

import pandas as pd
#Ref: https://codereview.stackexchange.com/questions/217065/calculate-levenshtein-distance-between-two-strings-in-python
from Levenshtein import distance as levenshtein_distance
import tldextract
import json
import yaml
import re
import math
import traceback
import sys, os
from datetime import datetime
import time
from datetime import timezone
import re
import subprocess
import pydig
import ipwhois
import pyasn
from geoip import geolite2
from collections import Counter
from string import printable

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import blacklists

import requests
from bs4 import BeautifulSoup

import math
from collections import Counter

#See https://pypi.org/project/pyasn/ how to generate these files
asndb = pyasn.pyasn('/mnt/extra1/projects/phishing/data/ipasn.dat')
keyword_file = '/mnt/extra1/projects/phishing/data/keywords.csv'
top_1k_domain_file = '/mnt/extra1/projects/phishing/data/top_1k_domain_file'

def write_list_to_file(in_file, my_list):
   with open(in_file, 'w+') as f:
    for item in my_list:
        f.write("%s\n" % item)

def read_list_from_file(in_file):
   lines = []
   with open(in_file, 'r') as f:
     lines = f.read().splitlines()
   return lines

top_1k_domains = []
###top_1k_domains =  blacklists.get_top_alexa_domains(1000 #REMOVE
###write_list_to_file(top_1k_domain_file, top_1k_domains) #REMOVE
top_1k_domains = read_list_from_file(top_1k_domain_file)
top_1k_slds = []
for d in top_1k_domains:
   ext = tldextract.extract(d)
   if ext and ext.domain: top_1k_slds.append(ext.domain)

def extract_whois_info(domain):
   #domain = "cnn.com"
   #Ref = https://whois.icann.org/en/dns-and-whois-how-it-works

   tld_ex = tldextract.extract(domain)
   #WHOIS service can only be used with TLD+1 and not sub-domains
   if tld_ex:
      domain = tld_ex.registered_domain

   whois_server = ""
   whois_info = {}
   try:
      cmd = '/usr/bin/whois ' + domain
      output = subprocess.getoutput(cmd)
      if output:
         output = output.lower()
         output_list = output.split('\n')
         output_list = list(map(str.strip, output_list))
         for e in output_list:
           e = e.lower()
           #if 'Registrar WHOIS Server:' in e:
           if 'registrar whois server:' in e:
               #re_whois_server = re.match('Registrar WHOIS Server:(.+)', e)
               re_whois_server = re.match('registrar whois server:(.+)', e)
               if (re_whois_server):
                  whois_server = re_whois_server.group(1)
                  whois_server = whois_server.strip()
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)


   if not (whois_server): return whois_info

   try:
      cmd = '/usr/bin/whois -H -h ' + whois_server + ' ' + domain
      output = subprocess.getoutput(cmd)
      if output:
         output_list = output.split('\n')
         output_list = list(map(str.strip, output_list))
         for e in output_list:
           if ':' not in e: continue
           re_str = re.match('(.+?)\:(.+)', e)
           if re_str:
              key = re_str.group(1)
              key = key.strip()
              val = re_str.group(2)
              val = val.strip()
              if key not in whois_info: whois_info[key] = []
              whois_info[key].append(val)
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)
   return whois_info

def get_processed_whois_info(detection_time,domain,whois_info):
   result = {}
   #domain = 'survivebeingbroke.com'

   #The Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.
   #re_dom = re.match('(\.com|\.net|\.edu)$', domain, re.IGNORECASE)
   #print("############ " + domain)

   try:
      epoch_now = datetime.utcnow().timestamp()
      if detection_time:
          #epoch_now_t = convert_ts_to_epoch(detection_time)
           
          epoch_now = detection_time.timestamp()
          #epoch_now = epoch_now_t if epoch_now_t != -1 else epoch_now
          #print(detection_time)
          #print("ZZZZ: " + str(epoch_now))
      ###whois_info = extract_whois_info(domain, whois_info_obj)
      #print(whois_info)
      if len(whois_info) == 0: return result

      re_whois_pr_regex_str = 'GDPR Masked|REDACTED FOR PRIVACY|WhoisGuard Protected|Whois Privacy|Contact Privacy Inc|Privacy Service|Non-Public'
      re_whois_pr_regex_org = 'Domains By Proxy|Privacy Protect|WhoisGuard|Whois Privacy|GDPR Masked'
      whois_name = str(whois_info['Registrant Name'][0]) if 'Registrant Name' in whois_info and len(whois_info['Registrant Name']) > 0 else ""
      whois_org = str(whois_info['Registrant Organization'][0]) if 'Registrant Organization' in whois_info and len(whois_info['Registrant Organization']) > 0 else ""
      if whois_name and whois_name is not None:
         #print('--------------')
         #print(whois_name)
         re_whois_pr = re.match(re_whois_pr_regex_str,whois_name,re.IGNORECASE)
         result['is_whois_privacy'] = 1 if re_whois_pr else 0
      elif whois_org and whois_org is not None:
         re_whois_pr = re.match(re_whois_pr_regex_org,whois_org,re.IGNORECASE)
         result['is_whois_privacy'] = 1 if re_whois_pr else 0
      else:
         result['is_whois_privacy'] = 0

      dnssec = str(whois_info['DNSSEC'][0]) if 'DNSSEC' in whois_info and len(whois_info['DNSSEC']) > 0 else ""
      result['dnssec'] = dnssec

      registrar = str(whois_info['Registrar'][0]) if 'Registrar' in whois_info and len(whois_info['Registrar']) > 0 else ""
      result['registrar'] = registrar

      name_servers = whois_info['Name Server'] if 'Name Server' in whois_info and len(whois_info['Name Server']) > 0 else []
      name_servers.sort()
      result['ns'] = ','.join(name_servers) # json.dumps(name_servers)

      ns_sld_dict = {}
      ns_asn_dict = {}

      ns_geo_dict = {}

      result['ns_sld'] = []
      result['ns_geo'] = []

      if name_servers and name_servers is not None:
         for ns in name_servers:
            ns_ext = tldextract.extract(ns)
            ns_sld_dict[ns_ext.domain.lower()] = 1

            ns_ip_list = pydig.query(ns, 'A')
            if ns_ip_list and len(ns_ip_list) > 0:
               #How to enrich data to find asn from ip - https://justhackerthings.com/post/enriching-ips-with-python/
               try:
                  asndb_obj = asndb.lookup(ns_ip_list[0])
                  if asndb_obj[0] == '[]': asndb_obj[0] = ''
                  ns_asn_dict[asndb_obj[0]] = 1
               except Exception as e:
                  pass

               try:
                  geodb_obj = geolite2.lookup(ns_ip_list[0])
                  if geodb_obj.country == '[]': geodb_obj.country = ''
                  if geodb_obj: ns_geo_dict[geodb_obj.country.lower()] = 1
               except Exception as e:
                  pass

         ns_sld = list(ns_sld_dict.keys())
         ns_sld.sort()
         result['ns_sld'] = ','.join(ns_sld) # json.dumps(ns_sld)
         ns_geo = list(ns_geo_dict.keys())
         ns_geo.sort()
         result['ns_geo'] = ','.join(ns_geo) #umps(ns_geo)

      ns_asn = list(ns_asn_dict.keys())
      ns_asn.sort()
      #result['ns_asn'] = ','.join(ns_asn) # json.dumps(ns_asn)
      result['ns_asn'] = ','.join(str(x) for x in ns_asn)
      result['registrant_org'] = str(whois_info['Registrant Organization'][0]) if 'Registrant Organization' in whois_info and len(whois_info['Registrant Organization']) > 0 else ""
      result["registrant_country"] = str(whois_info['Registrant Country'][0]) if 'Registrant Country' in whois_info and len(whois_info['Registrant Country']) > 0 else ""

      creation_date_list = whois_info['Creation Date'] if 'Creation Date' in whois_info and len(whois_info['Creation Date']) > 0 else []
      result['creation_date_list'] = creation_date_list
      if type(creation_date_list) is list:
          creation_date_list_epoch = []
          init_creation_date_epoch = None
          if creation_date_list and len(creation_date_list) > 0:
             for u_dt_str in creation_date_list:
                 if u_dt_str.endswith('Z'): u_dt_str = u_dt_str[:-1]
                 try:
                    u_dt = datetime.strptime(u_dt_str, '%Y-%m-%dT%H:%M:%S.%f')
                 except (Exception, ValueError) as e:
                    try:
                       re_dt_str = re.match('(\d\d\d\d\-\d\d\-\d\d.?\d\d\:\d\d\:\d\d)', u_dt_str)
                       if re_dt_str: u_dt_str= re_dt_str.group(1)
                       u_dt = datetime.strptime(u_dt_str, '%Y-%m-%dT%H:%M:%S')
                    except (Exception, ValueError) as e:
                        try:
                           u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d %H:%M:%S')
                        except (Exception, ValueError) as e:
                             try:
                                u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d')
                             except (Exception, ValueError) as e:
                                u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d-T%H:%M:%S.%f')
                 creation_date_list_epoch.append(u_dt.timestamp())
             init_creation_date_epoch = max(creation_date_list_epoch)
             result['creation_date_list_epoch'] = creation_date_list_epoch
             result['init_creation_date_epoch'] = init_creation_date_epoch
      elif creation_date_list:
          result['init_creation_date_epoch'] = creation_date_list.timestamp()

      expiration_date_list = whois_info['Registrar Registration Expiration Date'] if 'Registrar Registration Expiration Date' in whois_info and len(whois_info['Registrar Registration Expiration Date']) > 0 else []
      result['expiration_date_list'] = expiration_date_list
      if type(expiration_date_list) is list:
          expiration_date_list_epoch = []
          last_exp_date_epoch = None
          if expiration_date_list and len(expiration_date_list) > 0:
              for u_dt_str in expiration_date_list:
                 if u_dt_str.endswith('Z'): u_dt_str = u_dt_str[:-1]
                 try:
                    u_dt = datetime.strptime(u_dt_str, '%Y-%m-%dT%H:%M:%S.%f')
                 except (Exception, ValueError) as e:
                    try:
                       re_dt_str = re.match('(\d\d\d\d\-\d\d\-\d\d.?\d\d\:\d\d\:\d\d)', u_dt_str)
                       if re_dt_str: u_dt_str= re_dt_str.group(1)
                       u_dt = datetime.strptime(u_dt_str, '%Y-%m-%dT%H:%M:%S')
                    except (Exception, ValueError) as e:
                        try:
                           u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d %H:%M:%S')
                        except (Exception, ValueError) as e:
                             try:
                                u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d')
                             except (Exception, ValueError) as e:
                                u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d-T%H:%M:%S.%f')
                 expiration_date_list_epoch.append(u_dt.timestamp())
              last_exp_date_epoch = max(expiration_date_list_epoch)
              result['expiration_date_list_epoch'] = expiration_date_list_epoch
              result['last_exp_date_epoch'] = last_exp_date_epoch
      elif expiration_date_list:
         result['last_exp_date_epoch'] = expiration_date_list.timestamp()

      updated_date_list = whois_info['Updated Date'] if 'Updated Date' in whois_info and len(whois_info['Updated Date']) > 0 else []
      result['updated_date_list'] = updated_date_list
      if type(updated_date_list) is list:
         updated_date_list_epoch = []
         last_update_date_epoch = None
         if updated_date_list and len(updated_date_list) > 0:
             for u_dt_str in updated_date_list:
                 if u_dt_str.startswith('0001-01-01'): continue
                 if u_dt_str.endswith('Z'): u_dt_str = u_dt_str[:-1]
                 try:
                    u_dt = datetime.strptime(u_dt_str, '%Y-%m-%dT%H:%M:%S.%f')
                 except (Exception, ValueError) as e:
                    try:
                       re_dt_str = re.match('(\d\d\d\d\-\d\d\-\d\d.?\d\d\:\d\d\:\d\d)', u_dt_str)
                       if re_dt_str: u_dt_str= re_dt_str.group(1)
                       u_dt = datetime.strptime(u_dt_str, '%Y-%m-%dT%H:%M:%S')
                    except (Exception, ValueError) as e:
                        try:
                           u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d %H:%M:%S')
                        except (Exception, ValueError) as e:
                             try:
                                u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d')
                             except (Exception, ValueError) as e:
                                u_dt = datetime.strptime(u_dt_str, '%Y-%m-%d-T%H:%M:%S.%f')
                 updated_date_list_epoch.append(u_dt.timestamp())
             #if last_update_date_epoch and len(last_update_date_epoch) > 0:
             if updated_date_list_epoch and len(updated_date_list_epoch) > 0:
                last_update_date_epoch = max(updated_date_list_epoch)
                result['updated_date_list_epoch'] = updated_date_list_epoch
                result['last_update_date_epoch'] = last_update_date_epoch
      elif updated_date_list:
         result['last_update_date_epoch'] = updated_date_list.timestamp()

      result['time_since_dom_reg'] = int(round((epoch_now - result['init_creation_date_epoch'])/(60*60*24),0)) if 'init_creation_date_epoch' in result else 0
      result['time_to_dom_exp'] = int(round((result['last_exp_date_epoch'] - epoch_now)/(60*60*24),0)) if 'last_exp_date_epoch' in result else 0
      result['domain_life_span'] = int(round((result['last_exp_date_epoch'] - result['init_creation_date_epoch'])/(60*60*24),0)) if ('last_exp_date_epoch' in result and 'init_creation_date_epoch' in result) else 0
      result['time_since_dom_update'] = int(round((epoch_now - result['last_update_date_epoch'])/(60*60*24),0)) if 'last_update_date_epoch' in result else 0
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)
   return result

def compute_domain_length(domain):
   return len(domain) if domain else 0

def domain_resolves(domain):
    ip_list = None
    try:
       ip_list = pydig.query(domain, 'A')
    except Exception as e:
       print(str(e))
       traceback.print_exc(file=sys.stdout)

    return 1 if ip_list is not None and ip_list and len(ip_list)>0 else 0

def load_keywords():
    kw_dict = {}
    for _, row in pd.read_csv(keyword_file).iterrows():
      kw_dict[row[0]] = 1
    return kw_dict

#Ref: https://pure.tugraz.at/ws/portalfiles/portal/25394076/156259641564590.pdf
def find_min_lev_distance(domain, kw_dict):
   ld_list = []
   for k in kw_dict:
      ld = levenshtein_distance(domain, k)
      ld_list.append(ld)
   return min(ld_list)

def find_no_of_sub_domains(domain):
   extract_result = tldextract.extract(domain)
   sub_domain_str = extract_result[0]
   domain_str = extract_result[1]
   suffix_str = extract_result[2]

   no_of_sub_domains = 0

   if domain_str and suffix_str:
      if sub_domain_str:
         sub_split_list = sub_domain_str.split('.')
         no_of_sub_domains = len(sub_split_list) + 2
      else:
         no_of_sub_domains = 2
   return no_of_sub_domains

#Ref: https://blog.hubspot.com/website/best-free-ssl-certificate-sources
#Ref: https://www.geckoandfly.com/24460/free-trusted-ssl-certificate/
def cert_issued_from_free_ca(cert_obj):
   '''
   O=Let's Encrypt
   O=DigiCert Inc
   OU=Instant SSL
   O=ZeroSSL
   O=\"Cloudflare, Inc.\"
   O=WoSign CA Limited
   '''
   if cert_obj is None: return 0
   return_code = 0
   free_ca_list = ['Let\'s Encrypt', 'GeoTrust', 'Instant SSL', 'ZeroSSL', 'Cloudflare', 'WoSign']
   issuer = cert_obj["issuer_name"]
   if issuer:
      issuer_list = issuer.split(',')
      for issuer_token in issuer_list:
           for free_ca in free_ca_list:
               if ('O=' + free_ca).lower() in issuer_token.lower(): 
                   return_code = 1
               elif ('OU=' + free_ca).lower() in issuer_token.lower():
                   return_code = 1

   if return_code == 0 and cert_obj: return_code = 0
   return return_code

#Ref: https://pure.tugraz.at/ws/portalfiles/portal/25394076/156259641564590.pdf
#Ref: https://www.spamhaus.org/statistics/tlds/
def has_suspicious_tld_in_domain(domain):
   suspicious_tld_list = ['bank', 'business', 'cc', 'center', 'cf', 'click', 'club', 'country', 'download', 'ga', 'gb', 'gdn', 'gq', 'info', 'kim', 'loan', 'men', 'ml', 'mom', 'online', 'party', 'pw', 'racing', 'ren', 'review', 'science', 'stream', 'study', 'support', 'tech', 'tk', 'top', 'vip', 'win', 'work', 'xin', 'xyz', 'fit', 'email', 'rest', 'london']
   extract_result = tldextract.extract(domain)
   suffix_str = extract_result[2]

   if suffix_str in suspicious_tld_list:
      return 1
   else:
      return 0

#Ref: https://pure.tugraz.at/ws/portalfiles/portal/25394076/156259641564590.pdf
def has_inner_tlds_in_sub_domain(domain):
   popular_tld_list = ['.com-', '-com.', '.net-', '.org-', 'cgi-bin', '.com-', '.net.', '.org.', '.com', '.gov-', '.gov.', '.gouv-', '-gouv-', '.gouv.']
   extract_result = tldextract.extract(domain)
   sub_domain_str = extract_result[0]
   domain_str = extract_result[1]
   part_without_tld = sub_domain_str + '.' + domain_str

   if sub_domain_str != '':
      for pop_tld in popular_tld_list:
         if pop_tld in part_without_tld:
            return 1
   return 0

def find_domain_tld(domain):
   extract_result = tldextract.extract(domain)
   return extract_result.suffix if extract_result else 'nodata'

def find_number_of_hyphens_in_subdomain(domain):
   extract_result = tldextract.extract(domain)
   sub_domain_str = extract_result[0]
   if sub_domain_str:
      return sub_domain_str.count('-')
   return 0

def find_number_of_subdomains(domain):
   extract_result = tldextract.extract(domain)
   sub_domain_str = extract_result[0]
   return sub_domain_str.count('.') + 1 if sub_domain_str and '.' in sub_domain_str else 0

def find_number_of_hyphens_in_domain(domain):
   return domain.count('-')

def find_number_of_digits_in_domain(domain):
   #Ref: https://stackoverflow.com/questions/24878174/how-to-count-digits-letters-spaces-for-a-string-in-python
   if domain: 
      return len(re.sub("[^0-9]", "", domain))
   else:
      return 0

def evaluate_shannon_entropy(domain):
    '''
    #Ref: https://github.com/ambron60/shannon-entropy-calculator
    stack = {}
    symbol_list = {}

    for character in domain:
        stack[character] = round(domain.count(character) / len(domain), 5)
        symbol_list[character] = domain.count(character)

    bit_set = [round(stack[symbol] * math.log2(stack[symbol]), 5) for symbol in stack]
    entropy = -1 * (round(sum(bit_set), 5))
    return entropy
    '''
    #Ref: https://stackoverflow.com/questions/2979174/how-do-i-compute-the-approximate-entropy-of-a-bit-string
    l = float(len(domain))
    return round(-sum(map(lambda a: (a/l)*math.log2(a/l), Counter(domain).values())),3)

def convert_ts_to_epoch(datetime_str):
   res = 0
   try:
      u_dt = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S') 
      res = u_dt.timestamp()
   except Exception as e:
      print(str(e))
   return res

def find_expired_certs(cert_obj):
    if cert_obj is None: return 0
    is_cert_expired = 0
    if cert_obj:
       utcnow = int(time.mktime(time.gmtime()))
       not_after = cert_obj['not_after']
       not_after_epoch = None
       not_after_epoch = convert_ts_to_epoch(not_after)
       if not_after_epoch != 0:
          time_to_expire = int(not_after_epoch) - int(utcnow)
          if time_to_expire > 0: return 1
    return 0

def find_cert_lifespan(cert_obj):
    if cert_obj is None: return 0
    not_before_epoch = convert_ts_to_epoch(cert_obj['not_before'])
    not_after_epoch = convert_ts_to_epoch(cert_obj['not_after'])
    lifespan_val = 0
    if not_before_epoch != 0 and not_after_epoch != 0:
       if not_before_epoch and not_after_epoch and not_after_epoch > not_before_epoch:
          lifespan_val = int(round((not_after_epoch-not_before_epoch)/(60*60*24),0))
    return lifespan_val

def find_cert_issuer_name(cert_obj):
   if cert_obj is None: return ""
   issuer_name = cert_obj['issuer_name']
   issuer_name_tokens = issuer_name.split(',')
   issuer_org = ''
   for token in issuer_name_tokens:
     if 'O=' in token:
        token = token.strip()
        re_org = re.match('O=(.+)', token)
        if re_org: issuer_org = re_org.group(1)
   return issuer_org

def find_cert_issuer_country(cert_obj):
   if cert_obj is None: return ""
   issuer_name = cert_obj['issuer_name']
   issuer_name_tokens = issuer_name.split(',')
   issuer_country = ''
   for token in issuer_name_tokens:
     if 'C=' in token:
        token = token.strip()
        re_country = re.match('C=(.+)', token)
        if re_country: issuer_country = re_country.group(1)
   return issuer_country

def find_no_of_consecutive_characters(domain):
   tot = 0

   #https://www.kite.com/python/answers/how-to-count-the-number-of-repeated-characters-in-a-string-in-python
   frequencies = Counter(domain)
   repeated = {}
   for key, value in frequencies.items():
      if value > 1:
         repeated[key] = value

   for key, value in repeated.items():
      tot += value

   return tot

def has_special_characters(domain):
   #regular expression with compiled method
   regex = re.compile('[@_!#$%^&*()<>?\|}{~:]') 

   if set(domain).difference(printable) or (regex.search(domain) is not None):
      #domain has special characters
      return 1
   else:
      #domain hasn't special characters
      return 0

def get_number_of_hyperlinks(content):
    soup= BeautifulSoup(content, 'html.parser')
    all_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            all_links.append(x.get('href'))

    return len(all_links) if all_links else 0

def get_int_ext_links_ratio(content,domain):
    soup= BeautifulSoup(content, 'html.parser')
    all_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            all_links.append(x.get('href'))
    no_int_links = 0
    no_ext_links = 0
    for link in all_links:
       if '://' + domain + '/' in link:
           no_int_links += 1
       else: 
           no_ext_links += 1
    if no_ext_links == 0: 
        return 0
    else:
        return round(no_int_links/no_ext_links,2)

def get_null_links_ratio(content):
    soup= BeautifulSoup(content, 'html.parser')
    all_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            all_links.append(x.get('href'))
    no_null_links = 0
    no_all_links = len(all_links)
    for link in all_links:
       if not link or link is None: no_null_links += 1
    if no_all_links == 0: return 0
    return round(no_null_links/no_all_links,2)

def get_external_css(content):
    no_ext_css = 0
    soup= BeautifulSoup(content, 'html.parser')
    for link in soup.find_all('link', href=True):
       if 'rel' in link and 'stylesheet' in link['rel']: no_ext_css += 1
       #print("Found the URL:", link['rel'])
    return no_ext_css

def get_empty_actions(content):
    chk_actions = ["", "#", "#nothing", "#doesnotexist","#null", "#void", "#whatever", "#content", "javascript::void(0)","javascript::void(0);", "javascript::;", "javascript"]
    no_of_empty_actions = 0

    soup= BeautifulSoup(content, 'html.parser')
    all_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            if x.get('href') in chk_actions: all_links.append(x.get('href'))
    return len(all_links)

def get_external_favicons(content,domain):
    no_of_ext_favicons = 0

    soup= BeautifulSoup(content, 'html.parser')
    for link in soup.find_all('link', href=True):
       if not link['href'].startswith('http'): continue #internal
       if '://' +  domain not in link['href']: continue #internal
       if 'rel' in link and 'shortcut icon' in link['rel']: 
           no_of_ext_favicons += 1
    return no_of_ext_favicons

def get_forms_with_empty_actions(content):
    no_of_forms = 0

    soup = BeautifulSoup(content, 'html.parser')
    for form in soup('form'):
        if 'action' in form and (form['action'] == "" or form['action'] == 'about:blank'):
           no_of_forms+= 1       
    return no_of_forms

def get_iframes_with_invisible_border(content):
    no_iframes = 0

    soup = BeautifulSoup(content, 'html.parser')
    counter = 0
    for x in soup.find_all('iframe'):
        if x.get('frameborder') and x.get('frameborder') == "0":
           no_iframes += 1
    return int(no_iframes)

def get_use_of_unsafe_anchors(content):
    no_anchors = 0
   
    unsafe_anchor_list = ['#', 'javascript', 'mailto']
    soup = BeautifulSoup(content, 'html.parser')

    counter = 0
    for x in soup.findAll('a'):
       if x.get('href') and x.get('href') is not None:
          for item in unsafe_anchor_list:
             if item in x.get('href'): no_anchors += 1
    return no_anchors

def get_no_of_empty_title(content):
    no_empty_title = 0
    soup = BeautifulSoup(content, 'html.parser')
    title_obj = soup.findAll('title')
    if title_obj is None: 
       no_empty_title += 1
    elif len(title_obj) == 0:
       no_empty_title += 1
    elif title_obj[0] == "":
       no_empty_title += 1
    return no_empty_title

def is_domain_withon_copyright_symbol(content, domain):
    is_domain_copyright = 0
    soup = BeautifulSoup(content, 'html.parser')
    #Ref: https://stackoverflow.com/questions/51332185/extracting-texts-contained-in-a-html-tag-with-a-copyright-symbol-using-python
    symbol = u'\N{COPYRIGHT SIGN}'.encode('utf-8')
    symbol = symbol.decode('utf-8')
    pattern = r'' + symbol
    copyright_texts_list = []
    for tag in soup.findAll(text=re.compile(pattern)):
        copyright_texts = tag.parent.text
        if not copyright_texts: continue
        copyright_texts_list_tmp = copyright_texts.split(" ")
        for t_item in copyright_texts_list_tmp:
           t_item = t_item.strip()
           if t_item.isnumeric() or t_item.startswith(symbol): continue
           copyright_texts_list.append(t_item.lower())
    ext = tldextract.extract(domain)
    #For beinign (legitimate) domains ignore
    if domain.lower() in top_1k_domains or ext.domain.lower() in top_1k_slds: return 0
    #print("ZZZZZZZZZ: " + str(copyright_texts_list))
    for c_item in copyright_texts_list:
       if c_item in top_1k_domains or c_item in top_1k_slds: is_domain_copyright = 1
    return is_domain_copyright
           

def get_no_of_mouseover_events(content):
    #Ref: https://stackoverflow.com/questions/11606091/python-beautifulsoup-get-onmouseover-attributes
    no_events = 0
    soup = BeautifulSoup(content, 'html.parser')
    event_obj = soup.findAll(onmouseover=True)
    print(event_obj)

def extract_content_heuristics(content, domain):
    number_of_links = get_number_of_hyperlinks(content)
    int_ext_links_ratio = get_int_ext_links_ratio(content, domain)
    #null_links_ratio = get_null_links_ratio(content)
    number_exteral_css = get_external_css(content)
    empty_actions = get_empty_actions(content)
    #external_favicons = get_external_favicons(content, domain)
    forms_with_empty_actions = get_forms_with_empty_actions(content)
    iframes_with_invisible_border =  get_iframes_with_invisible_border(content)
    unsafe_anchors = get_use_of_unsafe_anchors(content)
    empty_title = get_no_of_empty_title(content) 
    is_domain_withon_copyright_sym = is_domain_withon_copyright_symbol(content,domain)
    #no_of_mouseover_events = get_no_of_mouseover_events(content)

    data = {
       's_number_of_links': number_of_links,
       's_int_ext_links_ratio': int_ext_links_ratio,
       #'null_links_ratio': null_links_ratio,
       's_number_exteral_css': number_exteral_css,
       's_empty_actions': empty_actions,
       #'external_favicons': external_favicons,
       's_forms_with_empty_actions': forms_with_empty_actions,
       's_iframes_with_invisible_border': iframes_with_invisible_border,
       's_unsafe_anchors' : unsafe_anchors,
       's_empty_title': empty_title,
       #'no_of_mouseover_events': no_of_mouseover_events,
       's_is_domain_withon_copyright_sym': is_domain_withon_copyright_sym,
    }

    return data

def extract_heuristics(domain, cert, whois_info):
   cert_obj = None
   try:
      #Ref: https://stackoverflow.com/questions/15198426/fixing-invalid-json-escape
      cert_obj = yaml.load(cert, yaml.FullLoader)
   except Exception as e:
      traceback.print_exc(file=sys.stdout)
      pass

   #whois_info = get_whois_info(domain)

   kw_dict = load_keywords()
   min_lev_distance = find_min_lev_distance(domain, kw_dict)
   #print(min_lev_distance)
   #domain = '0167d575c907.xyz'
   no_of_sub_domains = find_no_of_sub_domains(domain)
   #print(no_of_sub_domains)
   is_cert_issued_from_free_ca = cert_issued_from_free_ca(cert_obj)
   #print(is_cert_issued_from_free_ca)
   suspicious_tld_in_domain = has_suspicious_tld_in_domain(domain)
   domain_tld = find_domain_tld(domain)
   #print(has_suspicious_tld)
   tlds_in_sub_domain = has_inner_tlds_in_sub_domain(domain)
   #print(had_tlds_in_sub_domain)
   number_of_hyphens_in_domain = find_number_of_hyphens_in_domain(domain)
   number_of_hyphens_in_sub_domain = find_number_of_hyphens_in_subdomain(domain)
   number_of_subdomains = find_number_of_subdomains(domain)
   #print(number_of_hyphens_in_sub_domain)
   shannon_entropy = evaluate_shannon_entropy(domain)
   #print(shannon_entropy)
   #t1 = int(time.time())
   #whois_info = get_whois_info(domain)
   #t2 = int(time.time())
   #print(whois_info)
   #print(t2-t1)
   domain_length = compute_domain_length(domain)
   #print(domain_length)
   number_of_digits = find_number_of_digits_in_domain(domain)
   #print(number_of_digits)
   is_domain_resolves = domain_resolves(domain)
   #print(is_domain_resolves)
   has_expired_certs = find_expired_certs(cert_obj)
   #print(has_expired_certs)
   cert_lifespan = find_cert_lifespan(cert_obj)
   #print(cert_obj)
   #print(cert_lifespan)
   cert_issuer_name = find_cert_issuer_name(cert_obj)
   #print(cert_issuer_name) 
   cert_issuer_country = find_cert_issuer_country(cert_obj)
   #print(cert_issuer_country)
   no_of_consecutive_characters = find_no_of_consecutive_characters(domain)
   #print(no_of_consecutive_characters)
   has_special_chars = has_special_characters(domain)

   data = {
     'w_is_whois_privacy': whois_info['is_whois_privacy'] if len(whois_info) > 0 else 0,
     'w_dnssec': whois_info['dnssec'] if len(whois_info) > 0 else "",
     'w_registrar': whois_info['registrar'].lower() if len(whois_info) > 0 else "",
     'w_ns': whois_info['ns'].lower() if len(whois_info) > 0 else "",
     'w_ns_sld': whois_info['ns_sld'] if len(whois_info) > 0 and 'ns_sld' in whois_info and len(whois_info['ns_sld'])>0 else "",
     'w_ns_geo': whois_info['ns_geo'] if len(whois_info) > 0 and 'ns_geo' in whois_info and len(whois_info['ns_geo'])>0 else "",
     'w_ns_asn': whois_info['ns_asn'] if len(whois_info) > 0 and 'ns_asn' in whois_info and len(whois_info['ns_asn'])>0 else "",
     'w_registrant_org': whois_info['registrant_org'].lower() if len(whois_info) > 0 and 'registrant_org' in whois_info else "",
     'w_registrant_country': whois_info['registrant_country'].lower() if len(whois_info) > 0 and 'registrant_country' in whois_info else "",
     'w_time_since_dom_reg': whois_info['time_since_dom_reg'] if len(whois_info) > 0 and 'time_since_dom_reg' in whois_info else 0,
     'w_time_to_dom_exp': whois_info['time_to_dom_exp'] if len(whois_info) > 0 and 'time_to_dom_exp' in whois_info else 0,
     'w_domain_life_span': whois_info['domain_life_span'] if len(whois_info) > 0 and 'domain_life_span' in whois_info else 0,
     'w_time_since_dom_update': whois_info['time_since_dom_update'] if len(whois_info) > 0 and 'time_since_dom_update' in whois_info else 0, 
     'd_min_lev_distance': min_lev_distance,
     'd_no_of_sub_domains': no_of_sub_domains,
     'd_number_of_subdomains': number_of_subdomains,
     'c_is_cert_issued_from_free_ca': is_cert_issued_from_free_ca,
     'd_has_suspicious_tld_in_domain': suspicious_tld_in_domain,
     'd_has_tlds_in_sub_domain': tlds_in_sub_domain,
     'd_domain_tld': domain_tld,
     'd_number_of_hyphens_in_domain': number_of_hyphens_in_domain,
     'd_number_of_hyphens_in_sub_domain': number_of_hyphens_in_sub_domain,
     'd_shannon_entropy': shannon_entropy,
     'd_domain_length': domain_length,
     'd_number_of_digits': number_of_digits,
     'd_is_domain_resolves': is_domain_resolves,
     'c_has_expired_certs': has_expired_certs,
     'c_cert_lifespan': cert_lifespan,
     'c_cert_issuer_name': cert_issuer_name.lower() if cert_issuer_name else "",
     'c_cert_issuer_country': cert_issuer_country.lower() if cert_issuer_country else "",
     'd_no_of_consecutive_characters': no_of_consecutive_characters,
     'd_has_special_chars': has_special_chars
   }

   return data 
