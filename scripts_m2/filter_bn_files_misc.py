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
#from nltk.corpus import stopwords
#from nltk.tokenize import word_tokenize

#Ref: https://stackoverflow.com/questions/2782097/is-there-a-built-in-package-to-parse-html-into-dom
html_string = ""

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import utils
from website import Website
import feature_extract

simhashes_to_skip = [
              '1805800038487239398', #<html><head></head><body>Table 'xmailv3_store.wrongstocklink' doesn't exist</body></html>
              '8906118505739837662', #<html><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">Too many requests</pre></body></html>
              '1437922443512693402', #If you want your website to be available on the Internet, open your webmasters panel and in the general settings page turn on websites availability
              '9211276104574665357',
              '540231057390865174' #<p align="center"><font face="Arial, Helvetica, sans-serif" size="+2" color="#0033CC"><b><font face="Verdana, Arial, Helvetica, sans-serif" color="#003399"> Sito web in manutenzione</font></b></font></p>
             ]
simhashes_to_skip = [x[:-1] for x in simhashes_to_skip]

#dest_file = '/mnt/extra2/projects/phishing/out/ph_template_results.csv'

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

def process_page():
   print("Running process_page()...")
   #global dest_file
   dest_file = '/mnt/extra1/projects/phishing/scripts_m2/filter/ph_template_results.csv'
   #html_page = '/mnt/extra2/projects/phishing/sites/mal_m1/zonasegurainisiasesionenlinea.com.html'
   #res = utils.extract_template_from_html(html_page)
   #print(res)

   try:
      if os.path.exists(dest_file): os.remove(dest_file)
   except Exception as e:
      traceback.print_exc(limit=2, file=sys.stdout)
      print("Error while deleting file ", dest_file)

   glob_files = glob.glob("/mnt/extra1/projects/phishing/scripts_m2/webpage_sources_p/*.json")
   for f in glob_files:
     res = utils.extract_template_from_html(f)
     line = f + '	' + str(res['simhash']) +  '\n'
     with open(dest_file, 'a+') as writer:
        writer.write(line)
     #print(res['formatted_text'])
     #print('---------------------------')

def evaluate_tfidf(json_file):
   content = ""
   #html_page = '/mnt/extra2/projects/phishing/sites/mal_m1/zonasegurainisiasesionenlinea.com.html'
   html_str = ""
   json_content = ""

   with open(json_file) as f:
      content = f.readlines()
      try:
         json_obj = json.loads(content)
         json_content = json_obj['source']
      except Exception as e:
         return {}
         
   for line in json_content:
      line = line.replace('\n','')
      html_str += line
   #print(html_str)
   tfidf_info = utils.extract_tfidf_info(html_str)
   #print(tdidf_info)
   return tfidf_info

def process_tfidf():
   glob_files = glob.glob("/mnt/extra1/projects/phishing/scripts_m2/webpage_sources_p/*.json")
   timeout_val = 5
   for f in glob_files:
      try:
         with timeout(seconds=timeout_val):
            res = evaluate_tfidf(f)
            print(f)
            print(res)
            print('---------------------------------') 
            #break #REMOVE
      except Exception as e:
        #non-english languages can throw an exception
        print(str(e))
        traceback.print_exc(file=sys.stdout)

#Ref: https://stackoverflow.com/questions/49820228/how-to-compare-the-similarity-of-documents-with-simhash-algorithm
def split_hash(str, num):
    return [ str[start:start+num] for start in range(0, len(str), num) ]

def make_dir(sdir):
      try:
        if not os.path.isdir(sdir):
           os.mkdir(sdir)
      except OSError as error:
        print(error)

def filter_by_key_phrases(json_file):
   #content = ""
   #ws = Website(jspath=json_file)

   #with open(html_file) as f:
   #   content = f.readlines()
   #content_str = ""
   #for line in content:
   #   line = line.strip()
   #   content_str += line
   '''
   content_str = ws.source

   soup = beatsop(content_str)

   title = soup.title.text.lower() if soup.title is not None else ""
   title = title.strip()
   if 'Account Suspended'.lower() in title: return 1
   if 'error' in title: return 1
   if 'DNS, Dynamic DNS, VPN, VPS and Web Hosting Provider'.lower() in title: return 1
   if 'Index of /'.lower() in title: return 1
   if '400 Bad Request'.lower() in title: return 1
   if 'Domains, Webspace, Domain Webhosting, Server-Hosting Provider'.lower() in title: return 1
   if 'Expired or Suspended'.lower() in title: return 1
   if 'web hosting'.lower() in title: return 1 #<title>site44 - absurdly simple web hosting</title>
   if 'Contact Support'.lower() in title: return 1 
   if 'Free Website'.lower() in title: return 1 #<title>Welcome to messagealertsupportmailalertconnecthomenslbnhj.000webhostapp.com Free Website</title>

   if 'This domain is registered at'.lower() in content_str.lower(): return 1
   if 'contact your hosting provider'.lower() in content_str.lower(): return 1 #If you are the owner of this website, please contact your hosting provider
   if 'data-adblockkey="MFww'.lower() in content_str.lower(): return 1 #data-adblockkey="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALquDFETXRn0Hr05fUP7EJT77xYnPmRbpMy4vk8KYiHnkNpednjOANJcaXDXcKQJN0nXKZJL7TciJD
   if 'Your domain name is not added to the database'.lower() in content_str.lower(): return 1
   if 'If you want your website to be available on the Internet, open your webmasters panel and in the general settings page turn on websites availability'.lower() in content_str.lower(): return 1
   if '<span class="related-searches-custom">Related Searches:</span>'.lower() in content_str.lower(): return 1
   if 'failed to open stream'.lower() in content_str.lower(): return 1 #<b>Warning</b>:  Unknown: failed to open stream: Permission denied in <b>Unknown</b> on line <b>0</b><br> 
   if 'This link is currently unavailable'.lower() in content_str.lower(): return 1 #<html><head></head><body><div align="center" style="font-size:12px;margin-top:40px;">This link is currently unavailable.<!-- err3 --></div></body></html>
   #if 'Your session has expired'.lower() in content_str.lower(): return 1
   '''
   res_state = feature_extract.filter_by_key_phrases(json_file)
   if res_state: return res_state
   res_state = feature_extract.filter_by_leg_landing_url(json_file)
   if res_state: return res_state

   return 0
   
def file_by_simhash(simhash_stripped):
   global simhashes_to_skip
   if simhash_stripped in simhashes_to_skip: return 1
   return 0

#retrn true if no form inpult fields
def is_filter_html_input_fields(html_file):
   #Filter html files with input fields
   #Ref: https://stackoverflow.com/questions/17226080/parsing-html-forms-input-tag-with-beautiful-soup
   content = ""
   with open(html_file) as f:
      content = f.readlines()
   content_str = ""
   for line in content:
      line = line.strip()
      content_str += line 
   soup = beatsop(content_str)
   txt_input = soup.findAll('input', {'type':'text'})
   #if no input fields in form, then filter
   if len(txt_input) == 0: return 1

   #if filter_by_key_phrases(content_str, soup): return 1

   return 0

def delete_file(fname):
   if os.path.exists(fname):
      os.remove(fname)

def copy_file(src_file, dest_dir):
   try:
      copy(src_file, dest_dir)
   except Exception as e:
      pass

def group_docs():
   print("Running group_docs()...")
   in_file = '/mnt/extra1/projects/phishing/scripts_m2/filter/ph_template_results.csv'
   out_dir = '/mnt/extra1/projects/phishingscripts_m2/sims/group_imgs'
   out_dir_ph_updated = '/mnt/extra1/projects/phishing/scripts_m2/ph_updated_src'
   #remove folders in out directory?
   if os.path.isdir(out_dir): rmtree(out_dir)
   make_dir(out_dir)
   if os.path.isdir(out_dir_ph_updated): rmtree(out_dir_ph_updated)
   make_dir(out_dir_ph_updated)

   content = ""
   with open(in_file) as f:
      content = f.readlines()
   res = {}
   shash_skipped = {}
   for line in content:
      line = line.replace('\n','')
      #print(line)
      line_arr = line.split('	')
      f_name = line_arr[0]
      f_name_png = ""
      shash = line_arr[1]

      h_length = 19
      hash_chunks = split_hash(shash, h_length)

      if hash_chunks[0] not in shash_skipped: 
          shash_skipped[hash_chunks[0]] = 1
      else:
          shash_skipped[hash_chunks[0]] += 1
      if filter_by_key_phrases(f_name):
         #if hash_chunks[0] not in shash_skipped: shash_skipped[hash_chunks[0]] = 1
         continue

      if file_by_simhash(hash_chunks[0]): continue
      ####if is_filter_html_input_fields(f_name): continue
      if hash_chunks[0] in shash_skipped and shash_skipped[hash_chunks[0]] > 1: continue

      ####if len(shash) != 20: continue
      #h_length = len(shash) - 1
      #print(hash_chunks)
      #print(hash_chunks[0])
      if shash not in res: res[shash] = []
      f_name_png = f_name 
      f_name_png = f_name_png.replace('json', 'png')

      copy_file(f_name, out_dir_ph_updated)
      copy_file(f_name_png, out_dir_ph_updated)

      res[shash].append(f_name_png)
   for pshash in res:
      sdir = out_dir + '/' + pshash
      im_files = res[pshash]
      make_dir(sdir)
      for im_f_name in im_files:
         s_dir_f = sdir  + '/' + os.path.basename(im_f_name)
         ###print(im_f_name + ' -- ' + s_dir_f)
         if os.path.exists(im_f_name):
            copyfile(im_f_name, s_dir_f)
   #print(res)
   dest_file_e = '/mnt/extra1/projects/phishing/scripts_m2/sims/simhash_counts.csv'
   ###delete_file(dest_file_e)
   for pshash in res:
       line = pshash + '	' + str(len(res[pshash])) + '\n'
       with open(dest_file_e, 'a+') as writer:
           writer.write(line)

def filter_pages():
   print("Running filter_pages()...")

   out_dir_ph_updated = '/mnt/extra1/projects/phishing/scripts_m2/bn_updated_src_misc'

   if os.path.isdir(out_dir_ph_updated): rmtree(out_dir_ph_updated)
   make_dir(out_dir_ph_updated)

   #global dest_file
   glob_files = glob.glob("/mnt/extra1/projects/phishing/scripts_m2/webpage_sources_b_misc/*.json")
   for f in glob_files:
       f_name = f
       if filter_by_key_phrases(f_name):
           continue

       f_name_png = f_name
       f_name_png = f_name_png.replace('json', 'png')

       copy_file(f_name, out_dir_ph_updated)
       copy_file(f_name_png, out_dir_ph_updated)






def main():
   ##print_date()
   ###process_page()
   #process_tfidf()

   ##print_date()
   ###group_docs()
   filter_pages()

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()

