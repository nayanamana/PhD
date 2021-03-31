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
from datetime import datetime
import time

#----------------------------------

def extract_features(dirname, data_path):
   #res =  build_feat_vect.build_feature_vector(dirname, model_dir + '/fvm.pkl')
   res =  build_feat_vect.build_feature_vector(dirname, data_path)
   #print(res)
   return res

def main():
  time_yesterday = datetime.now().timestamp() - 2*60*60*24
  date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday))

  in_dir = '/mnt/extra2/web_domains/workspace/filtered_ph_sources/' + str(date_yesterday)

  feature_data_dir = '/mnt/extra2/web_domains/workspace/ph_sources/fea_vec/'
  extract_features(in_dir, feature_data_dir + 'fea_vec_' + str(date_yesterday) + '.pkl')




### MAIN ###
if __name__ == "__main__":
    main()

