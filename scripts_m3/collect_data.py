#!/usr/local/bin/python3.8

import warnings
warnings.filterwarnings('ignore')

import requests

import sys, os, json
import subprocess
import traceback
from datetime import datetime,timedelta
import time
from datetime import timezone
import datetime
import re

import csv
import requests

from nltk import word_tokenize
from nltk.corpus import stopwords
from nltk import tag
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

import datetime

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

from sklearn import preprocessing

from sklearn.model_selection import train_test_split

from sklearn.ensemble import RandomForestRegressor

from sklearn.tree import export_graphviz
import pydot

#Disable warnings
pd.options.mode.chained_assignment = None  # default='warn'

# Import matplotlib for plotting and use magic command for Jupyter Notebooks
import matplotlib.pyplot as plt

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
import queue
import urllib.request

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
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

from datetime import datetime,timedelta
import time
import threading

#Ref: https://stackoverflow.com/questions/2130016/splitting-a-list-into-n-parts-of-approximately-equal-length
def chunk_it(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out


def extract_data_ex(dir_name, file_lines, is_phish):
   
   #import process_url

   for u in file_lines:
       print(u)
       process_url.fetch_and_save_data(u, is_phish, dir_name) 

#----------------------------------------------

def print_usage():
    print("USAGE: " + sys.argv[0] + " /mnt/extra1/projects/phishing/scripts_m3/url_lists/list_250321")

def main():
  if len(sys.argv) < 2:
     print("Input file not passed as arguement")
     print_usage()
     sys.exit(0)

  pros = []
  time_yesterday = datetime.now().timestamp() - 2*60*60*24
  date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday))

  #out_dir = '/mnt/extra2/web_domains/workspace/ph_sources/' + '250321'
  out_dir = '/mnt/extra2/web_domains/workspace/ph_sources/' + str(date_yesterday)
  #out_dir = '/mnt/extra2/web_domains/workspace/ph_sources/' + '250321_1'

  #phish_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/phishing'
  #benign_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/benign'
  #url_list = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/benign' #CHANGE
  #url_list = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/nd2203'
  #url_list = '/mnt/extra1/projects/phishing/scripts_m3/url_lists/list_250321'

  url_list = sys.argv[1]
  if not os.path.exists(url_list):
      print("url_list: " + url_list + " does not exist")
      print_usage()
      sys.exit(0)
      
  is_phish = 0

  file_lines = []
  with open(url_list) as f:
     file_lines = [line.strip() for line in f]

  extract_data_ex(out_dir, file_lines, is_phish)

  #no_of_partitions = 5
  #chunnks = chunk_it(file_lines, no_of_partitions)

  #extract_data_ex(out_dir, url_list, is_phish)
  #Ref: https://stackoverflow.com/questions/25889268/running-same-function-for-multiple-files-in-parallel-in-python
  #for i in range(1,no_of_partitions+1):
     #p = Process(target=extract_data_ex, args=(out_dir,chunnks[i-1],is_phish,))
     #pros.append(p)
     #p.start()
     #task_handler(out_dir,chunnks[i-1],is_phish)

  # block until all the threads finish (i.e. block until all extract_data_ex calls finish)    
  #for t in pros:
  #   t.join()


### MAIN ###
if __name__ == "__main__":
    main()

