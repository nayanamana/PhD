#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys,os

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

try:
    import Image
except ImportError:
    from PIL import Image

import pandas as pd
import pytesseract
from bs4 import BeautifulSoup

# import nltk - a library for NLP analysis
from nltk import word_tokenize
from nltk.corpus import stopwords
from nltk import tag
#from autocorrect import spell
from autocorrect import Speller
from sys import platform
import math

import WORD_TERM_KEYS
import WORD_TERM_KEYS_MOD
import re
import os
import codecs
import traceback

from Levenshtein import distance as levenshtein_distance
import tldextract

from collections import Counter

import signal

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
sys.path.append('/mnt/extra1/projects/phishing/scripts_m1/Gibberish-Detector')
import gib_score

import blacklists
import utils

import enchant
import wordninja
import subprocess

import dns
from bs4 import BeautifulSoup as beatsop

FILTER_BRANDS = WORD_TERM_KEYS_MOD.WORD_TERM_BRAND
WORD_TERMS = WORD_TERM_KEYS.WORD_TERM

keyword_file = '/mnt/extra1/projects/phishing/data/keywords.csv'

#Evaluate Alexa SLD that has a length of greater than 2 where the SLD is not numeric
sld_exceptions = ['mail','office','force','live']
#alexa_doms = blacklists.get_top_alexa_domains(100)
alexa_doms = blacklists.get_top_alexa_domains(500) #use Alexa top-500 instead of top-100 ?
alexa_doms_sld = []
for d in alexa_doms: 
    d_ext = tldextract.extract(d)
    sld = d_ext.domain
    if sld in sld_exceptions: continue
    if (len(sld) > 3 and (not sld.isnumeric())):
       alexa_doms_sld.append(sld)

#Populate top brands - https://brandirectory.com/rankings/global/table
top_brand_list = []
brands_file = '/mnt/extra2/projects/phishing/data/top_brands.csv'
with open(brands_file) as f:
    top_brand_list = f.readlines()
top_brand_list = [line.lower().strip() for line in top_brand_list]
#print(top_brand_list)

#Ref: CANTINA+: A Feature-Rich Machine Learning Framework for Detecting Phishing Web Sites
#Ref: https://www.cio.com/article/2893761/domain-keywords-used-to-spot-phishing-sites.html
sensitive_keywords = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm","update","security","login","billing"]

#Ref: https://w3techs.com/technologies/overview/top_level_domain (top-10 TLds) ~ as of Dec 31st 2020
top_tlds = ["com", "ru", "org", "net", "ir", "in", "au", "uk", "de", "ua"]

#sensitive_input = ['email', 'user', 'username', 'userid', 'login', 'usr', 'user_id', 'loginid', 'user_name', 'password', 'login_user', 'uname', 'phone', 'email', 'customer', 'card_type', 'card_number', 'card', 'account', 'accountnumber', 'account_name', 'accno', 'accid']
sensitive_input = ['user', 'username', 'userid', 'login', 'usr', 'user_id', 'loginid', 'user_name', 'password', 'login_user', 'card_type', 'card_number', 'card', 'account', 'accountnumber', 'account_name', 'accno', 'accid']

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

#WORD_TERM = WORD_TERM_KEYS.WORD_TERM

if platform == "linux" or platform == "linux2":
    pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"
elif platform == "darwin":
    # OS X
    pytesseract.pytesseract.tesseract_cmd = "/usr/local/bin/tesseract"
elif platform == "win32":
    # Win
    print ("please specify the path")
    # Include the above line, if you don't have tesseract executable in your PATH
    # Example tesseract_cmd: 'C:\\Program Files (x86)\\Tesseract-OCR\\tesseract'

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
   re_lang_match =  re.search('html lang="(.+?)"', content_str.lower())
   if re_lang_match:
     lang = re_lang_match.group(1)
     if lang and lang.lower()!="en": return 'lang='


   if '<body></body>'.lower() in content_str.lower(): return '<body></body>'.lower()
   if '<body>'.lower() not in content_str.lower(): return 'NOT <body>'.lower()
   if 'domain has been suspended'.lower() in content_str.lower(): return 'domain has been suspended'.lower()
   if 'banned your access'.lower() in content_str.lower(): return 'banned your access'.lower()
   if 'account may have been suspended'.lower() in content_str.lower(): return 'account may have been suspended'.lower()
   if '504 Gateway Time-out'.lower() in content_str.lower(): return '504 Gateway Time-out'.lower()
   if 'suspended'.lower() in content_str.lower(): return 'suspended'.lower()
   if 'hosting'.lower() in content_str.lower(): return 'hosting'.lower()
   if 'Loading..'.lower() in content_str.lower(): return 'Loading..'.lower()
   if 'You need to enable JavaScript'.lower() in content_str.lower(): return 'You need to enable JavaScript'.lower()
   if 'construccion</title>'.lower() in content_str.lower(): return 'construccion</title>'.lower()

   return 0

def filter_by_header(html_file):
   content = ""
   with open(html_file) as f:
      content = f.readlines()
   content_str = ""
   for line in content:
      line = line.strip()
      content_str += line

   soup = beatsop(content_str)

   skip_list = ['localhost']
   hd_list = soup.find_all(re.compile('^h[1-6]$'))
   for item in hd_list:
      if item is None: continue
      item = str(item.text)
      print(item)
      if item.lower() in skip_list:
          return 1
   return 0

def get_alexa_doms_sld():
   global alexa_doms_sld
   return alexa_doms_sld

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

def get_processed_whois_info(domain,whois_info):
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

   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)
   return result


def process_html_text(html_content):
    """
    :param html_path:
    :return:
    """
    soup = None
    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception as e:
        print(str(e))
        traceback.print_exc(file=sys.stdout)
        return None, None

    heads = '.'.join(t.text for t in soup.find_all(re.compile(r'h\d+')))
    things = '.'.join(p.text for p in soup.find_all('p'))
    tags = '.'.join(a.text for a in soup.find_all('a'))
    titles = '.'.join(t.text for t in soup.find_all('title'))

    raw = heads + ' ' + things + ' ' + tags + ' ' + titles
    sent = word_tokenize(raw)
    #tokenize html

    tokens = tag.pos_tag(sent)
    #_map = {i.lower():j for i,j in tokens}
    #remove no-alpha words

    words = [word.lower() for word, _ in tokens if word.isalpha()]
    #words = list(set(words))

    #remove stop words
    stop_words = set(stopwords.words('english'))
    words = [w for w in words if w not in stop_words]

    text_word_str = ' '.join(words)

    #form analysis
    forms = soup.find_all('form')
    num_of_forms = len(forms)
    candidate_attributes = ['type', 'name', 'submit', 'placeholder']
    attr_word_list = list()

    for idx, form in enumerate(forms):
        inputs = form.find_all('input')
        for i in inputs:
            for j in candidate_attributes:
                if i.has_attr(j):
                    attr_word_list.append(i[j])

    attr_word_str = ' '.join(attr_word_list)

    words = word_tokenize(attr_word_str)
    words = [word.lower() for word in words if word.isalpha()]

    # words = list(set(words))
    # remove stop words
    words = [w for w in words if w not in stop_words]
    attr_word_str = ' '.join(words)

    return text_word_str, attr_word_str

def process_img_text_ocr(img_txt_content):
    if not img_txt_content: return ''
    text_list = img_txt_content.split('\n')
    text = ''
    for line in text_list:
        line = line.strip()
        #line_list = line.split(' ')
        #for w in line_list:
        text += ' ' + line
    sent = word_tokenize(text.lower())
    words = [word.lower() for word in sent if word.isalpha()]

    stop_words = set(stopwords.words('english'))
    words = [w for w in words if w not in stop_words]
    ocr_text = ' '.join(words)
    return ocr_text

def contain_brand_in_html(html_content_p):
   if html_content_p:
      html_content_l = html_content_p.split(' ')
      for h in html_content_l:
         if h.lower() in WORD_TERM_KEYS.WORD_TERM_BRAND_M: 
            #print("## HTML: " + h.lower())
            #print('-----------------------------')
            #print(h.lower())
            return 1
   return 0

def contain_brand_in_img(img_txt_content_p):
   if img_txt_content_p:
      img_txt_content_l = img_txt_content_p.split(' ')
      for i in img_txt_content_l:
         if i.lower() in WORD_TERM_KEYS.WORD_TERM_BRAND_M: 
            #print("## IMG: " + i.lower())
            return 1
   return 0

def contains_login_info(img_txt_content_p):
   no_of_tokens = 0

   #tokens_to_check = ['email', 'password', 'user', 'username', 'mobile', 'phone']
   tokens_to_check = ['email', 'password', 'user', 'username']

   img_text_ocr = process_img_text_ocr(img_txt_content_p)
   img_text_ocr_l = img_text_ocr.split(' ')

   for ele in img_text_ocr_l:
      if ele.lower() in tokens_to_check:
          no_of_tokens=no_of_tokens+1

   r = int(no_of_tokens)
   #print("@@@@@@: " + str(r))
   return r

def number_of_forms(html_content_raw):
   no_of_forms = 0
   soup = BeautifulSoup(html_content_raw, 'html.parser')
   forms = soup.find_all('form')
   return len(forms)

def get_is_title_empty(html_content_raw):
    no_empty_title = 0
    soup = BeautifulSoup(html_content_raw, 'html.parser')
    title_obj = soup.findAll('title')
    if title_obj is None:
       no_empty_title += 1
    elif len(title_obj) == 0:
       no_empty_title += 1
    elif title_obj[0] == "":
       no_empty_title += 1
    return no_empty_title

def get_use_of_unsafe_anchors(html_content_raw):
    no_anchors = 0

    unsafe_anchor_list = ['#', 'javascript', 'mailto']
    soup = BeautifulSoup(html_content_raw, 'html.parser')


    counter = 0
    for x in soup.findAll('a'):
       if x.get('href') and x.get('href') is not None:
          for item in unsafe_anchor_list:
             if item in x.get('href'): no_anchors += 1
    return no_anchors

def get_iframes_with_invisible_border(html_content_raw):
    no_iframes = 0

    soup = BeautifulSoup(html_content_raw, 'html.parser')
    counter = 0
    for x in soup.find_all('iframe'):
        if x.get('frameborder') and x.get('frameborder') == "0":
           no_iframes += 1
    return int(no_iframes)

def get_external_css(html_content_raw):
    no_ext_css = 0
    soup= BeautifulSoup(html_content_raw, 'html.parser')
    for link in soup.find_all('link', href=True):
       if 'rel' in link and 'stylesheet' in link['rel']: no_ext_css += 1
       #print("Found the URL:", link['rel'])
    return no_ext_css

def get_forms_with_empty_actions(html_content_raw):
    chk_actions = ["", "#", "#nothing", "#doesnotexist","#null", "#void", "#whatever", "#content", "javascript::void(0)","javascript::void(0);", "javascript::;", "javascript"]
    no_of_empty_actions = 0

    soup= BeautifulSoup(html_content_raw, 'html.parser')
    all_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            if x.get('href') in chk_actions: all_links.append(x.get('href'))
    return len(all_links)

def get_number_of_hyperlinks(html_content_raw):
    soup= BeautifulSoup(html_content_raw, 'html.parser')
    all_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            all_links.append(x.get('href'))

    return len(all_links) if all_links else 0

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

def evaluate_shannon_entropy(domain):
    #Ref: https://stackoverflow.com/questions/2979174/how-do-i-compute-the-approximate-entropy-of-a-bit-string
    l = float(len(domain))
    return round(-sum(map(lambda a: (a/l)*math.log2(a/l), Counter(domain).values())),3)

def find_number_of_hyphens_in_domain(domain):
   return domain.count('-')

def find_number_of_digits_in_domain(domain):
   #Ref: https://stackoverflow.com/questions/24878174/how-to-count-digits-letters-spaces-for-a-string-in-python
   if domain:
      return len(re.sub("[^0-9]", "", domain))
   else:
      return 0

def compute_domain_length(domain):
   return len(domain) if domain else 0

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

#####################################################################

def evaluate_tfidf(html_str):
   #print(html_str)
   tfidf_info = []
   try:
      tfidf_info = utils.extract_tfidf_info(html_str)
   except Exception as e:
      return []
   tfidf_info_n = []
   #print(tdidf_info)
   for item in tfidf_info:
      key = item[0]
      val = item[1]
      if key.isalpha():
         tfidf_info_n.append((key, val))
   return tfidf_info_n

def popular_dom_in_domain(domain):
    global alexa_doms_sld
    if domain.endswith('google.com'): return 0
    for item in alexa_doms_sld:
       if item in domain: 
           #print(item + ' -- ' + domain)
           return 1
    return 0

def sensitive_keywords_in_domain(domain):
   global sensitive_keywords
   for item in sensitive_keywords:
       if item in domain:
           #print(item + ' -- ' + domain)
           return 1
   return 0

def out_of_position_tlds(domain):
   global top_tlds
   ext = tldextract.extract(domain)
   ext_u = '.'.join(ext[:2])
   for item in top_tlds:
       if '.' + item + '.' in ext_u:
           #print(item + ' -- ' + domain)
           return 1
   return 0

def links_to_login_pages(content, domain):
    #form analysis
    soup= BeautifulSoup(content, 'lxml')
    links = []
    login_links = []

    for link in soup.findAll('a', attrs={'href': re.compile("^http://")}):
        links.append(link.get('href'))

    for link in soup.findAll('a', attrs={'href': re.compile("^https://")}):
        links.append(link.get('href'))

    for link in links:
       #Ref: https://stackoverflow.com/questions/27745/getting-parts-of-a-url-regex
       re_login_link = re.search('^((http[s]?|ftp):\/)?\/?([^:\/\s]+)((\/\w+)*\/)([\w\-\.]+[^#?\s]+)(.*)?(#[\w\-]+)?', link)
       if re_login_link:
           login_page = re_login_link.group(6)
           if login_page and 'login' in login_page.lower():
              #print(login_page + ' -- ' + link)
              login_links.append(login_page)
    return 1 if len(login_links) > 0 else 0

def proportion_of_foreign_links(content, domain):
    #form analysis

    soup= BeautifulSoup(content, 'lxml')
    all_links = []
    external_links = []
    for x in soup.findAll('a'):
        if x.get('href') and x.get('href') is not None:
            all_links.append(x.get('href'))
    for link in all_links:
       re_link = re.search('://(.+?)/', link)
       if re_link:
           link_d = re_link.group(1)
           if link_d:
              link_d = link_d.replace('www.','')
              if domain != link_d:
                 external_links.append(link_d)

    #print(0 if len(all_links) == 0 else round(len(external_links)/len(all_links),2))
    return 0 if len(all_links) == 0 else round(len(external_links)/len(all_links),2)
    

def sensitive_input_fields(content, domain):
    #form analysis
    soup= BeautifulSoup(content, 'lxml')

    #forms = soup.find_all('form')
    #num_of_forms = len(forms)
    #candidate_attributes = ['type', 'name', 'submit', 'placeholder']
    #candidate_attributes = ['name']
    #attr_word_list = list()

    #input_types = ['email', 'password', 'text', 'tel', 'number']
    #input_types = ['password']

    inputs = soup.find_all('input')
    #for idx, form in enumerate(forms):
    #    inputs = form.find_all('input')
    #    for i in inputs:
    for i in inputs:
            input_type = i.get('type')
            pl_type = i.get('placeholder')

            if input_type and input_type.lower() == 'password': 
                #print("AAA: " + input_type.lower())
                return 1        

            for term in ['ssn', 'postcode', 'date of birth', "driver's license", 'zip', 'postal code']:
                if pl_type and pl_type.lower() in term:
                   #print("BB: " + pl_type + ' -- ' + term)
                   return 1
            #if (input_type not in input_types) and (pl_type not in input_types): continue
            #if 'password' in input_type:
            #  for j in candidate_attributes:
            #    if i.has_attr(j):
            #        attr_val = i.get(j)
                    #if j!='name': continue
            #        for s_key in sensitive_input:
            #              if s_key in attr_val:
                              #print(j + ' --- ' + domain + ' -- ' + input_type + ' -- '  +attr_val)
                              #print(input_type + '	' + attr_val)
            #                  return 1
    return 0

def bad_action_fields(content, domain):
    soup= BeautifulSoup(content, 'lxml')
    forms = soup.find_all('form')

    for idx, form in enumerate(forms):
       action = form.attrs.get("action")
       if action is None: continue
       action = action.lower()
       if action == '' or (action.startswith('./') and len(action)>2):
           #print(domain + ' -- ' + action)
           return 1
       #print(domain + ' --- ' + action)
       #re_action = re.search('//(.+?)/',action)
       #if re_action:
       #    ex_dom = re_action.group(1)
       #    domain = domain.replace('www','')
       #    if ex_dom:
       #         ex_dom = ex_dom.replace('www.','')
       #    ex_dom_ext = tldextract.extract(ex_dom)
       #    domain_ext = tldextract.extract(domain)
       #    if ex_dom_ext.domain != domain_ext.domain: #compare only the SLD part
       #        #print(domain + ' -- ' + ex_dom + ' -- ' + action)
       #        return 1
               #print(domain + ' -- ' + ex_dom)
    return 0

def null_links_in_footer(content, domain):
    soup= BeautifulSoup(content, 'lxml')
    #Ref: https://stackoverflow.com/questions/56184133/extract-urls-from-the-footer-of-a-web-page
    if soup.footer is not None:
       ft =  soup.footer
       if ft is not None:
         link_list =  [link['href'] for link in ft.find_all('a', attrs={'href': re.compile("^http://")})]
         for link in link_list:
            if link in ['#', '#skip', '#content']: return 1 #Ref: http://www.ijlera.com/papers/v2-i3/20.201703073.pdf
    return 0

def out_of_position_brand_names(content, domain):
    tfidf = evaluate_tfidf(content)
    tfidf_n = tfidf[-3:]
    tfidf_n_k = []
    for item in tfidf_n:
       tfidf_n_k.append(item[0])

    ext = tldextract.extract(domain)
    ext_u = '.'.join(ext[:2])
    for item in tfidf_n_k:
       if item in ext_u:
           #print(item + ' -- ' + domain)
           return 1
    return 0

def popular_terms_in_tfidf(content, domain):
    tfidf = evaluate_tfidf(content)
    tfidf_n = tfidf[-3:]
    tfidf_n_k = []
    for item in tfidf_n:
       #item = item.lower()
       #tfidf_n_k.append(item[0])
       if item[0] in WORD_TERMS: 
          #print(domain + ' --- ' +  item[0])
          #print(item[0])
          return 1
    return 0


def copyright_text_has_popular_domain(content, domain):
    #Ref; https://stackoverflow.com/questions/15125465/python-regex-and-the-copyright-symbol
    #re_copyright = re.search(u'\N{COPYRIGHT SIGN}.+?([a-zA-Z]+)', content)
    re_copyright = re.search(u'(\N{COPYRIGHT SIGN}.+?)<', content)
    #re_copyright = re.search(u'>(.+?(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN}).+?)<', content)

    exception_list = ['wordpress']
    if re_copyright:
        copyright_dom = re_copyright.group(1) 
        if copyright_dom: copyright_dom = copyright_dom.lower()
        #print(domain + ' --- ' + copyright_dom)
        copyright_token_list = copyright_dom.split(' ')
        for token in copyright_token_list:
          token = token.strip()
          if token and (not token.isalpha()): continue
          if token and (token in alexa_doms_sld or token in top_brand_list) and token not in exception_list: 
             #print(domain + ' --- ' + token)
             return 1
    return 0

# Assuming Linux. Word list may also be at /usr/dict/words.
# If not on Linux, grab yourself an enlish word list and insert here:
words = set(x.strip().lower() for x in open("/usr/share/dict/words").readlines())

# The above english dictionary for some reason lists all single letters as words.
# Remove all except "i" and "u" (remember a string is an iterable, which means
# that set("abc") == set(["a", "b", "c"])).
words -= set("bcdefghjklmnopqrstvwxyz")

# If there are more words we don't like, we remove them like this:
words -= set(("ex", "rs", "ra", "frobnicate"))


#Ref: https://stackoverflow.com/questions/6897214/breaking-a-string-into-individual-words-in-python
def substrings_in_set(s, words):
   if s in words:
        yield [s]
   for i in range(1, len(s)):
        if s[:i] not in words:
            continue
        for rest in substrings_in_set(s[i:], words):
            yield [s[:i]] + rest

#def longest_word_in_str_ratio_norm(domain):
#   global words

#   if domain == "": return 0
#   name = domain.partition(".")[0].lower()
#   found = set()
#   matches = []
#   for split in substrings_in_set(name,words):
#        found |= set(split)
#   for word in found:
#      matches.append(word)
#   if len(matches) == 0: return 0
#   longest_word = max(matches, key=len)
#   ratio = round(len(longest_word)/len(domain),1)
#   return 0 if ratio > 0.2 or ratio < 0.6 else 1

def longest_word_in_str_ratio_norm(domain):
   global words

   lw_list = [0,0,0,0,0,0,0,0,0,0]

   if domain == "": return lw_list
   name = domain.partition(".")[0].lower()
   found = set()
   matches = []
   for split in substrings_in_set(name,words):
        found |= set(split)
   for word in found:
      matches.append(word)
   if len(matches) == 0: return lw_list
   longest_word = max(matches, key=len)
   ratio = round(len(longest_word)/len(domain),1)

   lw_list_res = []
   counter = 1
   for i in lw_list:
      if counter == ratio*10:
         lw_list_res.append(1)
      else:
         lw_list_res.append(0)
      counter += 1

   
   #return 0 if ratio > 0.2 or ratio < 0.6 else 1
   #print(str(ratio) + ' -- ' + str(lw_list_res))
   return lw_list_res


def contain_digits(domain):
    ext = tldextract.extract(domain)
    return 1 if re.match('[0-9]', '.'.join(ext[:2])) else 0

def contain_hyphens(domain):
    ext = tldextract.extract(domain)
    return 1 if '-' in '.'.join(ext[:2]) else 0

def contain_hyphens_and_digits(domain):
    ext = tldextract.extract(domain)
    str_dom =  '.'.join(ext[:2])
    str_dom = str_dom.replace('www.','')
    if str_dom.startswith('xn-'): return 0
    return 1 if '-' in str_dom and re.match('[0-9]', str_dom) else 0

def get_randomness_score(domain):
    ext = tldextract.extract(domain)
    domain = ext.domain
    #if '-' in domain: domain = domain.replace('-','')
    domain = re.sub('[^a-zA-Z]+', '', domain)
    if not domain: return 0
    if len(domain) <= 25: return 0

    echnt = enchant.Dict("en_US")

    dom_split = wordninja.split(domain)
    word_count = 0
    no_word_count = 0
    for d_item in dom_split:
       if len(d_item) < 4: continue
       chk_res = echnt.check(d_item)
       if chk_res:
          word_count += 1
          #break 
       else:
          no_word_count += 1

    if no_word_count > 1: return 1

    return 0 if word_count else 1

    #if len(ext.domain) > 25 and gib_score.is_random(domain):
    #   return 1 
    #else:
    #   return 0

def get_domain_length(domain):
    return 1 if len(domain) > 35 else 0

def extract_domain_features(domain):
    dom_features = []
    is_pop_dom_in_domain = popular_dom_in_domain(domain)
    dom_features.append(is_pop_dom_in_domain)

    is_sensitive_keyword_in_domain = sensitive_keywords_in_domain(domain)
    dom_features.append(is_sensitive_keyword_in_domain)

    has_out_of_position_tlds = out_of_position_tlds(domain)
    dom_features.append(has_out_of_position_tlds)

    longest_word_in_dom_ratio_norm = longest_word_in_str_ratio_norm(domain)
    #print('yyyyyyyyyyyyyyy')
    #print(longest_word_in_dom_ratio_norm)
    dom_features.extend(longest_word_in_dom_ratio_norm)

    #has_digits = contain_digits(domain)
    #dom_features.append(has_digits)

    #has_hyphens = contain_hyphens(domain)
    #dom_features.append(has_hyphens)

    has_hyphens_digits = contain_hyphens_and_digits(domain)
    dom_features.append(has_hyphens_digits)

    randomness_score = get_randomness_score(domain)
    dom_features.append(randomness_score)
    #print('--------------------------')
    #print(domain + ' -- ' + str(randomness_score) + "A" )

    domain_length = get_domain_length(domain)
    dom_features.append(domain_length)

    return dom_features

def extract_content_features(content, domain):
    content_features = []
    sen_input_feilds = sensitive_input_fields(content, domain)
    content_features.append(sen_input_feilds)

    has_bad_action_fields = bad_action_fields(content, domain)
    content_features.append(has_bad_action_fields)

    #has_out_of_position_brand_names = out_of_position_brand_names(content, domain)
    #content_features.append(has_out_of_position_brand_names)

    has_popular_terms_in_tfidf = popular_terms_in_tfidf(content, domain)
    content_features.append(has_popular_terms_in_tfidf)

    has_pop_dom_in_copyright = copyright_text_has_popular_domain(content, domain)
    content_features.append(has_pop_dom_in_copyright)

    has_links_to_login_pages = links_to_login_pages(content, domain)
    content_features.append(has_links_to_login_pages)

    #has_null_links_in_footer = null_links_in_footer(content, domain)
    #content_features.append(has_null_links_in_footer)

    #exceed_proportion_of_foreign_links = proportion_of_foreign_links(content, domain)
    #content_features.append(exceed_proportion_of_foreign_links)

    return content_features 
   

def feature_vector_extraction(domain, html_raw_content, img_txt_raw_content):
    """
    :param candidate: a candidate object
    :return: the feature vector
    it consists of three components: img-text, html-text, form-text
    """
    kw_dict = load_keywords()

    #print ("Analyse source and image at:")
    #print (candidate.source_html)
    #print (candidate.img_path)

    #if os.path.exists(candidate.source_html) and os.path.exists(candidate.img_path):
    #if domain and html_raw_content and img_txt_raw_content:
    if domain and html_raw_content:
        try:
            #img_text = get_img_text_ocr(candidate.img_path)
            final_v = []

            #print (img_text)
            dom_features = extract_domain_features(domain)
            con_features = extract_content_features(html_raw_content, domain)

            final_v.extend(dom_features)
            final_v.extend(con_features)
            #print(domain)
            #print(dom_features)
            #print('---------------------------')
            #html_content_p = process_html_text(html_raw_content)
            '''
            html_page_content = html_content_p[0]
            html_form_content  = html_content_p[1]
            img_txt_content_p = process_img_text_ocr(img_txt_raw_content)

            #whois_obj = extract_whois_info(domain)
            #whois_p = get_processed_whois_info(domain, whois_obj)
            #ns = whois_p["ns"]

            login_info_in_input_fields = contains_login_info(html_form_content)
            is_title_empty = get_is_title_empty(html_raw_content)
            #use_of_unsafe_anchors = get_use_of_unsafe_anchors(html_raw_content) 
            ###iframes_with_invisible_borders = get_iframes_with_invisible_border(content)
            ###external_css = get_external_css(content)
            #forms_with_empty_actions = get_forms_with_empty_actions(html_raw_content)
            #number_of_hyperlinks = get_number_of_hyperlinks(html_content)
            #no_of_forms =  number_of_forms(html_content)

            #brand_in_html = contain_brand_in_html(html_page_content)
            brand_in_img = contain_brand_in_img(img_txt_content_p)

            domain_no_of_consec_chars = find_no_of_consecutive_characters(domain)
            #domain_shannon_entropy = evaluate_shannon_entropy(domain)
            domain_number_of_hyphens = find_number_of_hyphens_in_domain(domain)
            domain_number_of_digits = find_number_of_digits_in_domain(domain)
            #domain_length = compute_domain_length(domain)
            domain_min_lev_distance = find_min_lev_distance(domain, kw_dict)

            ####text_word_str, num_of_forms, attr_word_str = get_structure_html_text(content)
            #img_v = text_embedding_into_vector(img_text)
            ###txt_v = text_embedding_heuristics(text_word_str)
            ###form_v = text_embedding_heuristics(attr_word_str)
            #final_v = img_v + txt_v + form_v + [num_of_forms]
            #final_v = [txt_v] + [form_v] + [num_of_forms] + [is_title_not_empty] + [use_of_unsafe_anchors] + [iframes_with_invisible_borders] + [external_css] + [forms_with_empty_actions] + [number_of_hyperlinks]
            #final_v = [num_of_forms] + [is_title_not_empty] + [use_of_unsafe_anchors] + [iframes_with_invisible_borders] + [external_css] + [forms_with_empty_actions] + [number_of_hyperlinks]
            ###final_v = [no_of_forms] + [login_info_in_input_fields] + [is_title_empty] + [brand_in_html] + [brand_in_img] + [domain_no_of_consec_chars] + [domain_shannon_entropy] + [domain_number_of_hyphens] + [domain_number_of_digits] + [domain_length] + [domain_min_lev_distance]
            final_v = [login_info_in_input_fields] + [is_title_empty] + [domain_no_of_consec_chars] + [domain_number_of_hyphens] + [domain_number_of_digits] + [brand_in_img] #+ [domain_min_lev_distance]
            '''
            return final_v

        except:
            traceback.print_exc(file=sys.stdout)
            print ("error happened! maybe your img/html-source format is not acceptable?")
            return None

