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

#import blacklists
#import utils

import enchant
import wordninja
import subprocess

import dns
from bs4 import BeautifulSoup as beatsop

from website import Website

import tldextract

benign_dom_list = []
benign_site_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/benign_1'

with open(benign_site_file) as f:
   lines = []
   for line in f:
      line = line.strip()
      line = line.replace('www.','')
      re_dom = re.search('://(.+?)/', line)
      if re_dom:
         benign_dom_list.append(re_dom.group(1))
      else:
         re_dom = re.search('://(.+)', line)
         if re_dom:
            benign_dom_list.append(re_dom.group(1))

#print(benign_dom_list)

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

def filter_by_leg_landing_url(json_file):
   global benign_dom_list
   other_land_urls = ['microsoftonline.com', 'google.com', 'paypal.com', 'amazon.com']
   benign_dom_list.extend(other_land_urls)

   ws = Website(jspath=json_file)
   landurl = ws.landurl

   ext = tldextract.extract(landurl)
   sld = ext.registered_domain
   if sld: sld = sld.replace('www.','')

   for ele in benign_dom_list:
      #if landurl and (landurl.endswith('.' + ele) or ('://' + ele in landurl) or ('www.' +  ele in landurl) or ('.' + ele + '/' in landurl)): return 1
      if landurl and (sld == ele): return 1
   return 0

def filter_by_key_phrases(json_file):
   #global benign_dom_list
   content = ""
   #with open(html_file) as f:
   #   content = f.readlines()
   #content_str = ""
   #for line in content:
   #   line = line.strip()
   #   content_str += line
   #other_land_urls = ['microsoftonline.com', 'google.com', 'paypal.com', 'amazon.com']
   #benign_dom_list.extend(other_land_urls)

   ws = Website(jspath=json_file)
   content_str = ws.source
   #landurl = ws.landurl

   #for ele in benign_dom_list:
   #   if landurl and (landurl.endswith('.' + ele) or ('://' + ele in landurl) or ('www.' +  ele in landurl) or ('.' + ele + '/' in landurl)): return 1

   text_str = ""

   try:
      text_str = ws.text
   except Exception as e:
      pass

   if text_str: text_str.strip()
   if (not text_str) or text_str == "": return 1
   if text_str and text_str.lower() == "loading": return text_str.lower()

   soup = beatsop(content_str)

   title = soup.title.text.lower() if soup.title is not None else ""
   title = title.strip()

   skip_source_list = ['This domain is registered at', 'contact your hosting provider', 'data-adblockkey="MFww', 'Your domain name is not added to the database', 'If you want your website to be available on the Internet, open your webmasters panel and in the general settings page turn on websites availability', '<span class="related-searches-custom">Related Searches:</span>', 'failed to open stream', 'This link is currently unavailable', "coming soon", "opening soon", "webpackJsonpparking-lander", "web hosting", "is For Sale", "free domain name", "parked domain", "EN CONSTRUCTION", "under construction", "checkdomain", "parking", "sell domain", "sell a domain", "buy domain", "buy a domain", "Domains For Sale", "This site can’t be reached", "Activate your domain", '<body></body>', 'domain has been suspended', 'banned your access', 'account may have been suspended', '504 Gateway Time-out', 'suspended', 'hosting', 'Loading..', 'You need to enable JavaScript', 'You need to enable JavaScript', 'construccion</title>', 'Error. Page cannot be displayed. Please contact your service provider for more details.', 'Erreur 404', 'Fatal error', 'This item might not exist or is no longer available', 'Suspected Phishing Site Ahead', 'This site will not work properly without JavaScript. Please enable JavaScript in your browser or update your browser to newest version.', '<title>Redirecting...</title>', 'This site is blocked due to abuse', 'There might be a problem with the requested link', 'Blog', 'Not found -', 'Please Wait ...', '>Processing...<', 'DataPage does not exist.', 'Compte suspendu', 'Loading please wait You will be redirected to the account page to resolve the problem', 'website is currently not available', 'Attempt to reach a \"phishing\" or \"malware\" site', '<body>Hello world</body>', 'Page not found', 'Error 404 Page', '<title>\u6ca1\u6709\u627e\u5230\u7ad9\u70b9</title>', '<title>Sorry, site has been closed</title>', 'Not Found', 'Starting dev server', 'Your browser is not supported', 'Please wait while we redirect you', 'This domain is free to take', 'This resource is no longer available', 'Hoal probando 123..', 'OOPS! THAT PAGE CAN\u2019T BE FOUND.\nIt looks like nothing was found at this location.', '404 Not Found', 'This page has been reported as unsafe', 'Stop! Deceptive page ahead', 'This site is currently unavailable', 'Page not found', 'The page has moved','URL you entered doesn\u2019t exist','Please wait while we are checking your browser','We\'re sorry, you are not allowed to proceed','You have an error in your SQL syntax','Website under maintenance','Upload your website','Something not right here','This domain has been terminated for abuse','PHISHING','Use of undefined constant','this will throw an Error in a future version of PHP','has blocked access','website you were trying to reach is temporarily unavailable','Please check back soon','Server Blacklist Site','Connection denied by Geolocation Setting','Related Searches:','This page has been reserved for future use', 'HTTP request sent, awaiting response','Link has been banned','landing page is not available','Internal error','Unterminated comment starting','Nginx server','Error connecting to MySQL server','Site Web indisponible','Page is not available','There was a minor issue on the server','warning:','Invalid URL','invalid or expired URL','Our automated systems have detected a potentially unsafe site','Directory Listing','unknown newsletter']

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
   if '404'.lower() in title: return '404'.lower()
   if 'redirection'.lower() in title: return 'redirection'.lower()

   for item in skip_source_list:
      if item.lower() in content_str.lower(): return item.lower()

   return 0

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


