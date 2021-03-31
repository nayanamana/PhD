#!/usr/local/bin/python3.8

import warnings
warnings.filterwarnings('ignore')

import sys, os, json
import subprocess
import traceback
from requests_html import HTMLSession

from html.parser import HTMLParser
from htmldom import htmldom
import glob,signal
from shutil import copy, copyfile, rmtree
from bs4 import BeautifulSoup as beatsop
import datetime
from datetime import datetime
import time
#from nltk.corpus import stopwords
#from nltk.tokenize import word_tokenize

#Ref: https://stackoverflow.com/questions/2782097/is-there-a-built-in-package-to-parse-html-into-dom
html_string = ""

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
#import utils
from website import Website
import feature_extract

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

def print_date():
   now = datetime.datetime.now()
   print (now.strftime("%Y-%m-%d %H:%M:%S"))

def make_dir(sdir):
      try:
        if not os.path.isdir(sdir):
           os.mkdir(sdir)
      except OSError as error:
        print(error)

def filter_by_key_phrases(json_file):
   res_state = feature_extract.filter_by_key_phrases(json_file)
   if res_state: return res_state
   #res_state = feature_extract.filter_by_leg_landing_url(json_file)
   #if res_state: return res_state

   return 0
   
def delete_file(fname):
   if os.path.exists(fname):
      os.remove(fname)

def copy_file(src_file, dest_dir):
   try:
      copy(src_file, dest_dir)
   except Exception as e:
      pass


def filter_pages():
   print("Running filter_pages()...")

   time_yesterday = datetime.now().timestamp() - 2*60*60*24
   date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday))

   #out_dir_ph_updated = '/mnt/extra1/projects/phishing/scripts_m2/ph_updated_src'
   source_dir = '/mnt/extra2/web_domains/workspace/ph_sources/' + str(date_yesterday)
   out_dir_ph_updated = '/mnt/extra2/web_domains/workspace/filtered_ph_sources/' + str(date_yesterday)

   if os.path.isdir(out_dir_ph_updated): rmtree(out_dir_ph_updated)
   make_dir(out_dir_ph_updated)

   #global dest_file
   glob_files = glob.glob(source_dir + "/*.json")
   for f in glob_files:
       f_name = f
       if filter_by_key_phrases(f_name):
           continue

       f_name_png = f_name
       f_name_png = f_name_png.replace('json', 'png')

       copy_file(f_name, out_dir_ph_updated)
       copy_file(f_name_png, out_dir_ph_updated)






def main():
   filter_pages()

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

