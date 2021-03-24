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

from datetime import datetime

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import feature_extract

threshold_days = 7


def get_phishtank_domains():
   global threshold_days
   phishtank_file = '/var/tmp/phish'

   resp_json = None
   with open(phishtank_file) as json_file:
      resp_json = json.load(json_file)

   url_dict = {}

   out_file = '/var/tmp/phish_out'
   if os.path.exists(out_file): os.remove(out_file)

   f = open("/var/tmp/new_phish_domains", "w+")

   counter = 0

   for j_obj in resp_json:
            #if counter > 10: break #REMOVE
            url_str = j_obj['url']
            verification_time = j_obj["verification_time"]
            verification_time = verification_time.replace('+00:00','')

            #ver_utc_time = datetime.strptime(verification_time, "%Y-%m-%dT%H:%M:%S.%fZ")
            ver_utc_time = datetime.strptime(verification_time, "%Y-%m-%dT%H:%M:%S")

            ver_epoch_time = (ver_utc_time - datetime(1970, 1, 1)).total_seconds()

            url_orig = url_str
            re_skip_url = re.search('://(.+?)/.+', url_str)
            if re_skip_url: continue

            re_url = re.search('://(.+?)/', url_str)
            if (re_url):
               dom_str = re_url.group(1)
               if (dom_str):
                   tmp_dom_str = dom_str
                   tmp_dom_str = tmp_dom_str.replace('www.','')

                   #ext = tldextract.extract(tmp_dom_str)
                   whois_info_obj = feature_extract.extract_whois_info(tmp_dom_str)
                   if len(whois_info_obj) == 0: continue
                   #print(whois_info_obj)
                   if 'Creation Date' not in whois_info_obj: continue
                   dom_cr_date_str = whois_info_obj['Creation Date']
                   dom_cr_date_str_1 = ''
                   if dom_cr_date_str and len(dom_cr_date_str) > 0:
                      dom_cr_date_str_1 = dom_cr_date_str[0]
                      dom_cr_date_str_1 = dom_cr_date_str_1.replace('Z','')
                   dom_cr_date_epoch = 0
                   if dom_cr_date_str_1:
                       #print(dom_cr_date_str_1)
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

                   #url_dict[url_str] = {'domain': dom_str, 'verification_time': verification_time, 'url': url_str, 'ver_time_epoch': ver_epoch_time, 'dom_cr_date_epoch': dom_cr_date_epoch, 'delta_days': delta_days}
                   #print(url_dict[url_str])

                   if delta_days <= threshold_days:
                      url_dict[url_str] = {'domain': dom_str, 'url_str': url_orig}
                      #print(url_dict[url_str])
                      print(url_orig + ',' + dom_str)
                      f.write(url_orig + ',' + dom_str + '\n')
                      counter += 1

                      #with open(out_file, 'a') as the_file:
                      #     line = dom_str + '   ' + url_str + ' ' + verification_time + '       ' + dom_cr_date_str_1 + '       ' + str(delta_days)
                      #     the_file.write(line + '\n')
   f.close()
   return url_dict


def main():
    ph_url_dict = get_phishtank_domains()
    print(ph_url_dict)


### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

