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
import dns
from bs4 import BeautifulSoup as beatsop
import os.path

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

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
#import feature_extract
#import blacklists
#import utils
#import ct
#from heuristics import extract_heuristics
#from ml_fn import *
#import predict
#import WORD_TERM_KEYS

#import heuristics
import signal

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from bs4 import BeautifulSoup

import process_url
import build_feat_vect

from pytz import timezone
tz = timezone('EST')

#FILTER_KEYS =  WORD_TERM_KEYS.FILTER_KEYS

#----------------------------------

def extract_dom_from_url(dom):
   if '://' in dom:
      re_dom = re.search('://(.+?)/', dom)
      if re_dom:
         return re_dom.group(1)
      else:
          re_dom = re.search('://(.+)', dom)
          if re_dom:
            return re_dom.group(1)
   else:
      return dom

def extract_data_ex(dir_name, mal_file, benign_file):
   mal_lines = []
   bn_lines = []

   #REMOVE THIS BLOCK LATER
   '''
   mal_lines_prev = []
   phish_file_prev = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/phishing_1_prev'
   with open(phish_file_prev) as f:
     mal_lines_prev = [line.strip() for line in f]
   '''
   with open(mal_file) as f:
     for line in f:
        line = line.strip()
        #if line not in mal_lines_prev:
        mal_lines.append(line)
 

   dom_collect_cache= {} 
   for u in mal_lines:
       print('------------------------------------')
       print(u)
       dom = extract_dom_from_url(u)
       if dom in dom_collect_cache:
          continue
       else:
          dom_collect_cache[dom] = 1
       is_phish = 1
       process_url.fetch_and_save_data(u, is_phish, dir_name) 
   
   '''
   with open(benign_file) as f:
     bn_lines = [line.strip() for line in f]

   for u in bn_lines:
       print(u)
       is_phish = 0
       process_url.fetch_and_save_data(u, is_phish, dir_name)
   '''

def extract_features(dirname, model_dir):
   res =  build_feat_vect.build_feature_vector(dirname, model_dir + '/fvm.pkl')
   #print(res)
   return res

def main():
  #url  = 'www.paypal-me-alessandra-martini.com'
  #url = 'lankapage.com'
  #url = 'cnn.com'
  #url = 'mydesk.morganstanley.com'

  #out_page_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_out_b_orig'
  #dom = 'mydesk.morganstanley.com'

  #out_page_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_out_m_orig'
  #out_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_sources_p'

  #is_phish = 1
  #extract_data(out_dir, is_phish)

  out_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_sources_p_test'
  phish_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/openphish'
  benign_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/benign_new'
  extract_data_ex(out_dir, phish_file, benign_file)


  ####model_dir = '/mnt/extra1/projects/phishing/scripts_m2/model'
  #####extract_features(out_dir, model_dir)




### MAIN ###
if __name__ == "__main__":
    main()

