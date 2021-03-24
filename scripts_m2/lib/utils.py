import warnings
warnings.filterwarnings('ignore')

import sys,sys,json,os
from requests_html import HTMLSession
from seleniumwire import webdriver  # Import from seleniumwire
from selenium.webdriver.firefox.options import Options
from datetime import datetime
import gzip

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import subprocess
import traceback
import time
from datetime import timezone
import re

import csv

import mysql.connector
from mysql.connector import Error

from collections import OrderedDict
from multiprocessing import Process
import random
import requests
import pandas as pd
import numpy as np

import signal

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

import blacklists
import ct
from heuristics import extract_heuristics
from website import Website

from pytz import timezone
tz = timezone('EST')

from bs4 import BeautifulSoup
from bs4 import NavigableString
from bs4 import Comment
from simhash import Simhash

from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

mysql_user = 'root'
mysql_pwd = 'mysql'
mysql_db = 'phishing_results_schema'

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_3/phishing_results_2.sql'

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

   """ Connect to MySQL database """
   print("Connecting to mysql database [phishing_results_schema]...")
   conn = None
   try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            print('Connected to MySQL database - phishing_results_schema')
            return conn

   except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def connect_result():
    """ Connect to MySQL database """
    #print("Connecting to mysql database [phishing_results_schema]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            #print('Connected to MySQL database - phishing_results_schema')
            return conn

    except Error as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def end_node(tag):
    #if tag.name not in ["div", "p", "li"]:
    #    return False
    if isinstance(tag,NavigableString): #if str return
        return False
    if not tag.text: #if no text return false
        return False
    elif len(tag.find_all(text=False)) > 0: #no other tags inside other than text
        return False
    return True #if valid it reaches here

def replace_tags(html_str):
  soup = BeautifulSoup(html_str, 'html.parser')
  for node in soup.find_all():
     print(node)
     print('-------------------------------')

#Ref: https://gist.github.com/cbcafiero/c363006a36672d6803cbdee836af97ef
def extract_template_from_html(json_path):
   content = ""
   html_str = ""
   #with open(json_path) as f:
   #   content = f.readlines()

   ws = Website(jspath=json_path)

   json_content = ""
   try:
      json_content = ws.source
   except Exception as e:
      return {}
      
   for line in json_content:
      line = line.replace('\n','')
      html_str += line
   #Ref: https://gist.github.com/cbcafiero/c363006a36672d6803cbdee836af97ef
   #replace_tags(html_str)
   #Ref: https://stackoverflow.com/questions/54265391/find-all-end-nodes-that-contain-text-using-beautifulsoup4
   #soup = BeautifulSoup(html_str, "html.parser")
   soup = BeautifulSoup(html_str, "lxml")
   #remove cmments
   #Ref: https://itqna.net/questions/68805/remove-comment-tag-and-its-contents-beautifulsoup-4
   for comments in soup.findAll(text=lambda text:isinstance(text, Comment)):
      comments.extract()
   nodes_content = soup.find_all(end_node)
   for node in nodes_content:
     node.string = "NV"

   for elm in soup():
      for attr in elm.attrs:
         elm.attrs[attr] = "AV"

   #Replace all spaces with empty strings
   formatted_text = str(soup)
   #formatted_text = formatted_text.replace(' ','')
   ######formatted_text = re.sub(r'>(\s+)+<', '><', formatted_text)

   #print(formatted_text)

   ft_split_list = formatted_text.split('<')
   formatted_text_1 = ""

   for f in ft_split_list:
     re_t = re.search('(.+>)(.*)', f)
     if re_t:
       prefix = re_t.group(1)
       tail_part = re_t.group(2)
       formatted_text_1 += '<' + prefix
       #if tail_part in ['NV', 'AV']: formatted_text_1 += tail_part
       if tail_part in ['NV', 'AV']:
          #print(tail_part)
          formatted_text_1 += tail_part
   
   #print('--------------')
   #print(formatted_text_1)
   #print('-------------')
   #Replace text between nodes
   ###formatted_text = re.sub(r'>([^NV|AV]+?)<', '>TV<', formatted_text)
   #print(str(soup))
   s_hash = Simhash(formatted_text_1).value

   return {'formatted_text': formatted_text_1, 'simhash': s_hash}

def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True

def get_raw_text_from_html(html_text):
   #Ref; https://stackoverflow.com/questions/1936466/beautifulsoup-grab-visible-webpage-text
   soup = BeautifulSoup(html_text, 'html.parser')
   texts = soup.findAll(text=True)
   visible_texts = filter(tag_visible, texts)  
   return u" ".join(t.strip() for t in visible_texts)

def extract_tfidf_info(html_text):
   raw_text = get_raw_text_from_html(html_text)
   stop_words = set(stopwords.words('english'))
   word_tokens = word_tokenize(raw_text)
   filtered_sentence = [w for w in word_tokens if not w in stop_words]
   filtered_sentence = ' '.join(filtered_sentence)
   #print(filtered_sentence)
   #evaluate TF-IDF
   #Ref: https://towardsdatascience.com/natural-language-processing-feature-engineering-using-tf-idf-e8b9d00e7e76
   vectorizer = TfidfVectorizer()
   vectors = vectorizer.fit_transform([filtered_sentence])
   feature_names = vectorizer.get_feature_names()
   dense = vectors.todense()
   denselist = dense.tolist()
   df = pd.DataFrame(denselist, columns=feature_names)
   #return df['account'][0]
   #print(df.to_dict())
   d_res = df.to_dict()
   d_res_n = {}
   for k in d_res:
      val = d_res[k][0]
      d_res_n[k] = val
   #Ref: https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value
   sorted_dict = sorted(d_res_n.items(), key=lambda x: x[1])  
   #print(sorted_dict)
   return sorted_dict


