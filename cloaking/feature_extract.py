#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import print_function

import os
import os.path
import sys
import re
import json
import simplejson
import datetime
import traceback
from langdetect import detect 
import requests
import robotparser
import socket
import sqlite3

reload(sys)
sys.setdefaultencoding('utf8')

from rake_nltk import Rake

# Uses stopwords for english from NLTK, and all puntuation characters by
# default
r = Rake()

#user_dir = os.path.expanduser('~')
user_dir = '/mnt/extra2/projects/0919_cl'
openwpm_util_path = '/home/naya/install/OpenWPM/automation/utilities/'
base_path = user_dir + '/cloaking/'

file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)
sys.path.append(openwpm_util_path)

socket.setdefaulttimeout(10) #Set a 10 sec global default timeout

try:
    import Image
except ImportError:
    from PIL import Image

import pytesseract
from bs4 import BeautifulSoup

from domain_utils import get_ps_plus_1

#import nltk
#nltk.download()

# import nltk - a library for NLP analysis
from nltk import word_tokenize
from nltk.corpus import stopwords
from nltk import tag
from autocorrect import spell
from sys import platform


#import WORD_TERM_KEYS
import re
import os
import codecs

import argparse
import numpy as np
from sklearn import decomposition
from sklearn.externals import joblib
from sklearn.metrics import jaccard_similarity_score

from langdetect import detect_langs
from googletrans import Translator

from nltk.tokenize import RegexpTokenizer
from stop_words import get_stop_words
from nltk.stem.porter import PorterStemmer
from gensim import corpora, models
import gensim


###import model
import feature_extract

from PIL import Image
import imagehash

import shutil

#from simhash import fingerprint
#import simhash

import sys
import time

from simhash import Simhash
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

import urllib2
import re

import glob

alexa_domains = {}
sites_visited = {}

#mal_dom_file = '/mnt/extra1/projects/cloaking/mal_doms/vt_domains_1'
mal_info_dict = {}

#WORD_TERM = WORD_TERM_KEYS.WORD_TERM

ignore_pattern = r'(buy this domain|may be for sale|buy domain|get this domain|This domain may be for sale|The domain.+?is for sale|parked domain|domain parking|web page is parked|to buy.+?for your website name|the domain may be available|domain owned by godaddy|the domain is available for sale|The domain .+? may be for sale|Register Your Favorite.+?Domain Name here|DOMAIN SALE)'

unusual_pattern = r'(404.+?file or directory not found|sorry you have been blocked|coming soon|page cannot be displayed|403 forbidden|internal server error|internal error|server connection terminated|too many rquests|404 not found|502 bad gateway|bot user agent)'


dir_results = base_path + '/cl_imgs/'
if not os.path.exists(dir_results + '/content_diff'): os.makedirs(dir_results + '/content_diff')
if not os.path.exists(dir_results + '/img_diff'): os.makedirs(dir_results + '/img_diff')
if not os.path.exists(dir_results + '/ele_diff'): os.makedirs(dir_results + '/ele_diff')

file_name_img_diff = dir_results + '/' + "img_diff_res.txt"
file_name_content_diff = dir_results + '/' + "content_diff_res.txt"
file_name_ele_diff = dir_results + '/' + "ele_diff_res.txt"

if os.path.exists(file_name_img_diff):
   os.remove(file_name_img_diff)
if os.path.exists(file_name_content_diff):
   os.remove(file_name_content_diff)
if os.path.exists(file_name_ele_diff):
   os.remove(file_name_ele_diff)

sub_dirs = ["img_diff","content_diff","ele_diff","files_dynamic"]
for sub_dir in sub_dirs:
   if os.path.isdir(dir_results + '/' + sub_dir):
      shutil.rmtree(dir_results + '/' + sub_dir)
      os.mkdir(dir_results + '/' + sub_dir)

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

#Logs - check is all are needed?
f_exist_in_alexa = open(base_path + "/logs/exists_in_alexa", "w+")
f_similar_img_diff_links = open(base_path + "/logs/similar_img_diff_links", "w+")
f_domains_to_ignore = open(base_path + "/logs/domains_to_ignore", "w+")
f_all_sites = open(base_path + "/logs/all_sites", "w+")
f_possible_cloaking = open(base_path + "/logs/possible_cloaking", "w+")
f_googlebot_unusual_content = open(base_path + "/logs/bot_unusual_content", "w+")
f_skip_files = open(base_path + "/skip_files", "w+")
f_infected = open(base_path + "/infected", "w+")
f_exceptions = open(base_path + "/exceptions", "w+")


def is_alexa_domain(url):
   m = re.search('(.+?:\/\/)(.+?)\/', url)
   if m:
      dom  = m.group(2)
      dom = dom.replace('www.', '')
      #get PS+1 of the domain
      #print("Prev Domain: " + str(dom))
      t_dom = get_ps_plus_1(m.group(1) + dom)
      if t_dom: 
         if t_dom in alexa_domains: return 1 

      return 1 if dom in alexa_domains else 0
   return 0


#def get_img_text_ocr(img_path):
#    """
#    :param img_path:
#    :return:
#    This part is to extract words from an image. We apply OCR technique to read texts from images.
#    More info on OCR can be found:
#    https://github.com/madmaze/pytesseract
#    """
#    img = Image.open(img_path)
#    text = pytesseract.image_to_string(img, lang='eng')
#    sent = word_tokenize(text.lower())
#    words = [word.lower() for word in sent if word.isalpha()]
#
#    stop_words = set(stopwords.words('english'))
#    words = [w for w in words if w not in stop_words]
#    ocr_text = ' '.join(words)
#    return ocr_text

#def get_img_raw_text_ocr(img_path):
#    img = Image.open(img_path)
#    text = pytesseract.image_to_string(img, lang='eng')
#    text = text.encode('utf-8').strip()
#    return text

#def get_img_text_from_ocr_txt(img_txt_path):
#    text = ''
#    f = codecs.open(img_txt_path, 'r', encoding='utf-8')
#    for line in f.readlines():
#        line = line.strip()
#        text += ' ' + line
#    f.close()
#    sent = word_tokenize(text.lower())
#    words = [word.lower() for word in sent if word.isalpha()]
#    stop_words = set(stopwords.words('english'))
#    words = [w for w in words if w not in stop_words]
#    ocr_text = ' '.join(words)
#    return ocr_text

def get_links_from_html(html_path):
    """
    :param html_path:
    :return:
    """
    data = codecs.open(html_path, 'r', encoding='utf-8').read()
    #try:
    #    soup = BeautifulSoup(data, "lxml")
    #except Exception as inst:
    #    f = open('log-error.log', 'a')
    #    f.write("SoupParse Exception: " + str(type(inst)) + " " + str(html_path) + '\n')
    #    f.close()
    #    return None, None, None

    #tags_arr = []
    #for a in soup.find_all('a'):
    #   tags_arr.append(a.text)
    #for link in soup.findAll('a', attrs={'href': re.compile("^http([s]{1}?)://")}):
    #   tags_arr.append(link.get('href'))
    return json.loads(data)

#Extract header meta data
def get_header_metadata(html_path):
   meta_data_tags = {}
   data = codecs.open(html_path, 'r', encoding='utf-8').read()
   soup = BeautifulSoup(data, "lxml")
   keywords = soup.findAll(attrs={"name": re.compile(r"keywords", re.I)})
   #if keywords and len(keywords) > 0 and 'content' in keywords[0]: meta_data_tags['keywords'] = keywords[0]['content'].encode('utf-8')
   if (keywords): 
       for x in keywords:
          if 'keywords' not in meta_data_tags: meta_data_tags['keywords'] = []
          try:
             if (x['content']): meta_data_tags['keywords'].append(x['content'].encode('utf-8'))
          except Exception as e:
               pass
   title = soup.title
   if title and title.string: meta_data_tags['title'] = title.string.encode('utf-8')
   desc = soup.findAll(attrs={"name": re.compile(r"description", re.I)})
   #if desc and len(desc) > 0 and 'content' in desc[0]: meta_data_tags['description'] = desc[0]['content'].encode('utf-8')
   if (desc):
       for x in desc:
          if 'description' not in meta_data_tags: meta_data_tags['description'] = []
          try:
             if (x['content']): 
                meta_data_tags['description'].append(x['content'].encode('utf-8'))
          except Exception as e:
             pass
   if 'keywords' in meta_data_tags and len(meta_data_tags['keywords']) > 0: meta_data_tags['keywords'] = meta_data_tags['keywords'][0]
   if 'description' in meta_data_tags and len(meta_data_tags['description']) > 0: meta_data_tags['description'] = meta_data_tags['description'][0]
   return meta_data_tags

def find_header_diff(br_h, bot_h):
   h_keys = ['title', 'keywords', 'description']
   descrep_h = {}

   for k in h_keys:
      br_h_val = str(br_h[k]) if k in br_h else ""
      bot_h_val = str(bot_h[k]) if k in bot_h else ""
      if k in br_h and k in bot_h:
         if br_h[k] != bot_h[k]:
            descrep_h[k] = {'br': br_h_val, 'bot': bot_h_val } 
      elif (k in br_h and k not in bot_h) or (k not in br_h and k in bot_h): 
         descrep_h[k] = {'br': br_h_val, 'bot': bot_h_val }
   return descrep_h if len(descrep_h) > 0 else ""

#Extract links in iframe documents
def extract_links_from_iframe_docs(iframe_body):
   data_b = codecs.open(iframe_body, 'r', encoding='utf-8').read()
   try:
        soup = BeautifulSoup(data_b, "lxml")
   except Exception as inst:
        f = open('log-error.log', 'a')
        f.write("SoupParse Exception: " + str(type(inst)) + " " + str(html_path) + '\n')
        f.close()
        return None, None, None

   tags_res = {}
   for link in soup.findAll('a'):
       lnk = link.get('href')
       if lnk not in tags_res: tags_res[lnk] = 1
   return tags_res.keys()

#If the text is not english, convert to English content
def get_body_from_html(html_path_r):
   the_contents_of_body_without_body_tags = ""
   #data = codecs.open(html_path, 'r', encoding='utf-8').read()
   data_r = codecs.open(html_path_r, 'r', encoding='utf-8').read()
   ln = ""
   text = ""
   try:
      #soup = BeautifulSoup(data, "lxml")
      #tag_arr = []
      #try:
      #   desc = soup.findAll(attrs={"name": re.compile(r"description", re.I)}) 
      #   if desc: tag_arr.append(desc[0]['content'].encode('utf-8'))
      #   keywords = soup.findAll(attrs={"name": re.compile(r"keywords", re.I)})
      #   if keywords: tag_arr.append(keywords[0]['content'].encode('utf-8'))

      #   if (soup.title.string):
      #       tag_arr.append(soup.title.string)
      #except Exception as e:
      #    pass

      #text_body = soup.get_text()
      #text = text_body
      #tag_arr.append(text_body)

      #tag_str = " ".join(tag_arr)
      #Strip English characters to solve issues with mixed language content with English
      #tag_str = re.sub("[A-Za-z0-9\!\@\#\$\%\^\&\*\(\)\[\]\{\}\;\:\'\"\?\/\>\<\-\+\=\.\,\_\\\|\`\:\~]", "", tag_str.strip())
      #text = ""

      det_obj = ""
      translator = Translator()
      try:
         det_obj = str(translator.detect(data_r))
      except Exception as e:
         det_obj = data_r
      match = re.search("Detected\(lang=(.+?), confidence=(.+?)\)", det_obj)
      if match:
          ln = match.group(1)
          con = match.group(2)
          if (ln != "en"):
              text = translator.translate(data_r, dest='en')
   except Exception as e:
      print(str(e))
      pass
   if text: 
      text = str(text) 
      text = text.strip()
   #print("TEXT: " + text)
   #print("######## LN: " + ln)


   r_text = text if text else str(data_r)
    
   return {'ln': ln , 'text': r_text}

def link_differ(l_arr_br, l_arr_bot):
   link_diff_list_br = []
   link_diff_list_bot = []
   for i in l_arr_br:
      if (re.match("^http([s]{1}?)://", str(i))):
         if i not in l_arr_bot: link_diff_list_br.append(i)
   for j in l_arr_bot:
      if (re.match("^http([s]{1}?)://", j)):
         if j not in l_arr_br: link_diff_list_bot.append(j)

   return {'br': link_diff_list_br, 'bot': link_diff_list_bot}  if len(link_diff_list_br) > 0 or len(link_diff_list_bot) else "" 

def get_redirected_url(redirect_path):
   if not os.path.exists(redirect_path): return ""
   data = codecs.open(redirect_path, 'r', encoding='utf-8').read()
   data = data.strip()
   match = re.search('\<(.+?)\>.+?\<(.+?)\>', data)
   if match:
     u1 = match.group(1)
     u2 = match.group(2)
     u1_t = u1
     u2_t = u2
     m1 = re.search('(.+)\/$', u1_t)
     if m1: u1_t = m1.group(1)
     m2 = re.search('(.+)\/$', u2_t)
     if m2: u2_t = m2.group(1)

     if (str(u1_t) != str(u2_t)):
        #print '*** ' + u1_t + ' -- ' + u2_t
        return u2
   else:
     return ""

def get_structure_html_text(html_path):
    """
    :param html_path:
    :return:
    """
    data = codecs.open(html_path, 'r', encoding='utf-8').read()
    try:
        soup = BeautifulSoup(data, "lxml")
    except Exception as inst:
        f = open('log-error.log', 'a')
        f.write("SoupParse Exception: " + str(type(inst)) + " " + str(html_path) + '\n')
        f.close()
        return None, None, None

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

    return text_word_str, num_of_forms, attr_word_str

def get_domain_html(html_path):
   #if not os.path.isfile(html_path): return '' #if file does not exist, return ''
   return codecs.open(html_path, 'r', encoding='utf-8').read()

def ignore_domain_html(data, match_str):
    #data = codecs.open(html_path, 'r', encoding='utf-8').read()
    data = unicode(str(data), "utf-8")
    m = re.search(match_str, data, re.IGNORECASE)
    return data if (m) else 0

def ignore_domain_img(data, match_str):
    m = re.search(match_str, data, re.IGNORECASE)
    return data if (m) else 0 

#def text_embedding_into_vector(txt_str):
#    """
#    :param text_str:
#    :return:
#    We split text into a list of features for training
#    """
#    texts = txt_str.split(' ')
#    texts = [spell(w).lower() for w in texts]
#    embedding_vector = [0]*(len(WORD_TERM) + 1)
#    for elem in texts:
#        # if it exist, we set the index plus one
#        # else the last position plus one
#        index = WORD_TERM.index(elem) if elem in WORD_TERM else -1
#        embedding_vector[index] += 1
#
#    return embedding_vector


def tokenize(sequence):
    words = word_tokenize(sequence)
    filtered_words = [word for word in words if word not in stopwords.words('english')]
    return filtered_words

def get_image_hash(img_path):
   algo = imagehash.dhash
   img = Image.open(img_path)
   hash = algo(img)
   return hash
   
def jaccard_similarity_custom(list1, list2):
    if (len(list1) == 0 and len(list2) == 0): return float(0)
    s1 = set(list1)
    s2 = set(list2)
    no_int = len(s1.intersection(s2))
    no_union = (len(s1.union(s2)) - no_int)
    if (no_union == 0): return float(0) 
    j_index = no_int / (len(list1 + list2) - no_int)
    #print str(no_int) + " -- " + str(len(list1 + list2) - no_int) + ' -- ' + str(j_index)
    return j_index
 
#def get_top_rank_from_page(content):
#    content_arr = content.split(' ')
#    #r.extract_keywords_from_text(content)
#    r.extract_keywords_from_sentences(content_arr)
#    rank_arr =  r.get_ranked_phrases()
#    #print rank_arr
#    return rank_arr[0] if len(rank_arr) > 0 else ""

#Get text given image
def image_to_text(img_raw_text):
   #im_text = str(image_to_text_raw(img_path, ln))
   im_text = img_raw_text
   ###im_text = unicode(im_text, errors='ignore')

   ocr_text = ""
 
   try:
      sent = word_tokenize(im_text.lower())
      words = [word.lower() for word in sent if word.isalpha()]

      stop_words = set(stopwords.words('english'))
      words = [w for w in words if w not in stop_words]
      ocr_text = ' '.join(words)
   except:
      ocr_text = im_text

   return ocr_text

#Get text given image - raw
def image_to_text_raw(img_path, ln):
   #lang_arr = ('en', 'zh', 'es', 'ar', 'pt', 'id', 'fr', 'ja', 'ru', 'de')
   m1 = re.search("(.+?)\-(.+?)", ln) 
   if m1: ln = m1.group(1)
   lang_2_to_3 = {'en': 'eng', 'zh': 'chi_sim', 'es': 'spa',
        'ar': 'ara', 'pt': 'por', 'id': 'ind', 'fr': 'fra', 'ja': 'jpn', 'ru': 'rus', 'de': 'deu', 'nl': 'dut'}

   translator = Translator()

   ln_3_code = "en"
   if ln: ln_3_code = lang_2_to_3[ln]
   res_img_text = ""
   img_text = ""
   try:
      img_text = pytesseract.image_to_string(img_path, lang=ln_3_code)
      if ln == "en":
         res_img_text = img_text
      else:
         res_img_text = translator.translate(img_text, dest='en')
   except Exception as e:
         res_img_text = img_text


   return res_img_text

#Get the highest rank topic (for English content only)
def gen_lda(doc_text):
   #Remove numberic characters
   doc_text = re.sub(r'[0-9]', "", doc_text) if doc_text else ""

   #Based on https://rstudio-pubs-static.s3.amazonaws.com/79360_850b2a69980c4488b1db95987a24867a.html
   tokenizer = RegexpTokenizer(r'\w+')

   #create English stop words list
   en_stop = get_stop_words('en')

   #Create p_stemmer of class PorterStemmer
   p_stemmer = PorterStemmer()

   texts = []

   #clean and tokenize document string
   doc_text = str(doc_text)
   raw = doc_text.lower()
   #Extract only words from string
   res_raw = re.findall(r'\w+', raw) 
   raw = str(res_raw)

   #generate LDA model
   try:
      tokens = tokenizer.tokenize(raw)

      #remove stop words from tokens
      stopped_tokens = [i for i in tokens if not i in en_stop]

      #stem tokens
      stemmed_tokens = [p_stemmer.stem(i) for i in stopped_tokens]

      #add tokens to list
      texts.append(stemmed_tokens)

      #turn our tokenized documents into a id <-> term dictionary
      dictionary = corpora.Dictionary(texts)

      if not dictionary or len(dictionary) == 0: return ""

      #convert tokenized documents into a document-term matrix
      corpus = [dictionary.doc2bow(text) for text in texts]

      ldamodel = gensim.models.ldamodel.LdaModel(corpus, num_topics=1, id2word = dictionary, passes=50)
      lda_obj = ldamodel.show_topics(num_topics=3, num_words=3, log=False, formatted=False)

      if (len(lda_obj) > 0 and len(lda_obj[0]) > 0):
         #print(lda_obj)
         #print(lda_obj[0][1])
         ot_obj = lda_obj[0][1]
         res = {}
         if (len(ot_obj) > 2 and len(ot_obj[0]) > 0 and len(ot_obj[1]) > 0 and len(ot_obj[2]) > 0):
            t_obj1 = ot_obj[0][0]
            t_val1 = ot_obj[0][1]
            t_obj2 = ot_obj[1][0]
            t_val2 = ot_obj[1][1]
            t_obj3 = ot_obj[2][0]
            t_val3 = ot_obj[2][1]
            #return t_obj1
            res["t1"] = {'name': t_obj1, 'val': t_val1}
            res["t2"] = {'name': t_obj2, 'val': t_val2}
            res["t3"] = {'name': t_obj3, 'val': t_val3}
            return res
      else:
         return ""
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)
      return ""


def write_content_to_file(content, dest_file):
    f_write = open(dest_file, "w+")
    f_write.write(content)
    f_write.close()

def is_mal_domain(domain_url):
   return '[]'
   v_m = VIRUSTOTAL_KEY_M
   v_o = VIRUSTOTAL_KEY_0
   v_1 = VIRUSTOTAL_KEY_1
   v_2 = VIRUSTOTAL_KEY_2
   v_3 = VIRUSTOTAL_KEY_3
   v_4 = VIRUSTOTAL_KEY_4
   v_5 = VIRUSTOTAL_KEY_5
   v_6 = VIRUSTOTAL_KEY_6
   v_7 = VIRUSTOTAL_KEY_7
   v_8 = VIRUSTOTAL_KEY_8
   v_9 = VIRUSTOTAL_KEY_9
   v_10 = VIRUSTOTAL_KEY_10

   api_key = v_m
   baseurl = "https://www.virustotal.com/vtapi/v2/"

   resp_str = ""
   vuln = []
   try:
      url = baseurl + "url/report"
      #domain = 'http://' + domain.strip()
      params = {'apikey': api_key, 'resource': domain_url, 'allinfo': True }
      response = requests.post(url, data=params)
      resp_json = response.json()
      if ("scans" in resp_json and "resource" in resp_json):
         resource = resp_json['resource']
         scans = resp_json['scans']
         for vt in scans:
            if scans[vt]['detected'] == True:
                vt_result = str({vt: scans[vt]['result']})
                vuln.append(vt_result) 
   except ValueError as e:
      print("Rate limit detected: " + str(e))
      traceback.print_exc(file=sys.stdout)
   except Exception as ex:
      print("Error detected: " + str(ex))
      traceback.print_exc(file=sys.stdout)

   return json.dumps(vuln)


def is_robot_txt_block(domain):
   #url = 'http://' + domain + "/"
   url = domain + '/'
   rp = robotparser.RobotFileParser()
   rp.set_url(url + 'robots.txt')
   rp.read()
   return rp.can_fetch("*", url)

def create_tables(conn_result):
   try:
      c = conn_result.cursor()
      sql_str = """CREATE TABLE IF NOT EXISTS sites
      (
         SITE           TEXT    NOT NULL,
         LIST           TEXT    NOT NULL
         );"""
      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS crawl_errors
      (
         SITE           TEXT    NOT NULL,
         CLIENT           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         ERROR_STRING  TEXT    NOT NULL,
         ERROR_TYPE  TEXT  NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS redirects
      (
         SITE           TEXT    NOT NULL,
         REDIRECTED_URL  TEXT   NOT_NULL,
         CLIENT           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         TYPE  TEXT  NOT NULL,
         VULN  TEXT NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS exceptions
      (
         SITE           TEXT    NOT NULL,
         CLIENT           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         TYPE  TEXT  NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS domains_ignored
      (
         SITE           TEXT    NOT NULL,
         CLIENT           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         TYPE	TEXT	NOT NULL,
         CONTENT  TEXT  NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS link_dissimilarity
      (
         SITE           TEXT    NOT NULL,
         CLIENT           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         LINK  TEXT  NOT NULL,
         CONTENT   TEXT NOT NULL,
         VULN  TEXT NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS iframe_links
      (
         SITE           TEXT    NOT NULL,
         CLIENT           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         LINK  TEXT  NOT NULL,
         VULN  TEXT NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS jac_similarity
      (
         SITE           TEXT    NOT NULL,
         SCORE  TEXT NOT NULL,
         BR_CONTENT   TEXT NOT NULL,
         BOT_CONTENT   TEXT NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS content_similarity
      (
         SITE           TEXT    NOT NULL,
         H_BT_BR	INT 	NOT NULL,
         H_BT_BOT        INT    NOT NULL,
         H_BT_ONE INT    NOT NULL,
         H_BT_TWO INT    NOT NULL,
         BR_CONTENT   TEXT NOT NULL,
         BOT_CONTENT   TEXT NOT NULL,
         SCORE  INT NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS header_similarity
      (
         SITE           TEXT    NOT NULL,
         ITER      TEXT    NOT NULL,
         BR_HEADER        TEXT    NOT NULL,
         BOT_HEADER        TEXT    NOT NULL,
         TYPE  TEXT NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS image_similarity
      (
         SITE           TEXT    NOT NULL,
         H_BT_BR        INT    NOT NULL,
         H_BT_BOT        INT    NOT NULL,
         H_BT_ONE INT    NOT NULL,
         H_BT_TWO INT    NOT NULL,
         BR_CONTENT   TEXT NOT NULL,
         BOT_CONTENT   TEXT NOT NULL,
         SCORE INT   NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS topic_similarity
      (
         SITE           TEXT    NOT NULL,
         BR_TOPIC_1        TEXT    NOT NULL,
         BOT_TOPIC_1        TEXT    NOT NULL,
         BR_TOPIC_2        TEXT    NOT NULL,
         BOT_TOPIC_2        TEXT    NOT NULL,
         BR_TOPIC_3        TEXT    NOT NULL,
         BOT_TOPIC_3        TEXT    NOT NULL,
         BR_PROB_1        TEXT    NOT NULL,
         BOT_PROB_1        TEXT    NOT NULL,
         BR_PROB_2        TEXT    NOT NULL,
         BOT_PROB_2        TEXT    NOT NULL,
         BR_PROB_3        TEXT    NOT NULL,
         BOT_PROB_3        TEXT    NOT NULL,
         MATCHED INT   NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      sql_str = """CREATE TABLE IF NOT EXISTS non_english_sites
      (
         SITE           TEXT    NOT NULL,
         LANG_BR        TEXT   NOT NULL,
         LANG_BOT       TEXT   NOT NULL
      );"""

      c.execute(sql_str)
      conn_result.commit()

      #c.execute("CREATE UNIQUE INDEX sites_SITE ON sites(SITE);")
      c.execute("CREATE INDEX crawl_errors_SITE ON crawl_errors(SITE);")
      conn_result.commit()
   except Exception as e:
     print("[CREATE_TABLE_ERROR] " + str(e))

def insert_data_to_table(db_file, table, data):
    conn_cl = sqlite3.connect(db_file)
    key_arr = []
    val_arr = []
    args_arr = []
    for key in data:
       key_arr.append(key)
       args_arr.append(data[key])
       val_arr.append('?')
    key_str = ','.join(key_arr)
    val_str = ','.join(val_arr)
    sql_str = "INSERT INTO " + table + " (" + key_str + ") VALUES (" + val_str + ")"
    c_insert = conn_cl.cursor()
    c_insert.execute(sql_str, args_arr)
    conn_cl.commit()

def process_crawl_log(db_file, log_path):
    conn_cl = sqlite3.connect(db_file)
    sql_in_sites = """INSERT INTO sites
                         (SITE, LIST)
                         VALUES (?, ?)"""
    sql_in_errors = """INSERT INTO crawl_errors
                         (SITE, CLIENT, ITER, ERROR_STRING, ERROR_TYPE)
                         VALUES (?, ?, ?, ?, ?)"""

    sql_get_sites_visited = """SELECT SITE from sites WHERE SITE NOT IN (SELECT SITE from crawl_errors)"""
 
    #counter = 0
    with open(log_path) as input_data:
       for line in input_data:
           #counter+=1
           #if counter > 10: break 
           m = re.search(r'\[SITE_VISIT\]\s+?(.+)', line.strip())
           if (m):
              site = m.group(1)
              #sites_visited[site] = 1
              c_in_sites = conn_cl.cursor()
              in_site_arg = (site, 'tranco')
              c_in_sites.execute(sql_in_sites, in_site_arg)
    #conn_cl.commit()

    #counter = 0
    with open(log_path) as input_data:
       for line in input_data:
           #counter+=1
           #if counter > 30: break
           m = re.search(r'\[ERROR_OUTER\]\s+?(.+?)\-(.+?)\s+?(.+?)\s+?(.+?)\s+?(.+)', line.strip())
           if (m):
             client = m.group(1)
             iter = m.group(2)
             url = m.group(3)
             e_type = m.group(4)
             e_str = m.group(5)
             e_str = e_str.replace('at ' + url, '')
             c_in_errors = conn_cl.cursor()
             in_error_args = (url.strip(), client.strip(), iter, e_str.strip(), e_type.strip())
             c_in_errors.execute(sql_in_errors, in_error_args)
    conn_cl.commit()

    cur_sel = conn_cl.cursor()
    cur_sel.execute(sql_get_sites_visited)
    rs = cur_sel.fetchall()
    for row in rs:
      sites_visited[row[0]] = 1

    conn_cl.close()    



####### MAIN ################

if __name__ == "__main__":

    #Populate alexa domains
    print("Populating popular domains...")
    with open(base_path + "/data/tranco-1m.csv") as f:
        for line in f:
           line = line.strip()
           line_arr = line.split(',')
           alexa_domains[line_arr[1]] = 1

    #url_file = base_path + '/data/ph_sites_1'
    url_file = '/home/naya/phd/ph_exp/results/all_cloaked_sites'
    data_dir = base_path + "/results"
    #data_dir = "/mnt/extra1/projects/cloaking/results_160319"
    #log_path = '/mnt/extra1/projects/cloaking/logs_160319/site_debug.log'
    log_path = base_path + '/logs/site_debug.log'
    bot_label = 'googlebot'
    br_label = 'chrome'

    #Create tables (SQLite)
    print("Cleaning database..")
    db_file = base_path + '/data/cloaking_results.db'
    if os.path.exists(db_file):
       os.remove(db_file)
    conn_cl = sqlite3.connect(db_file)
    create_tables(conn_cl)

    #Insert domains crawled and errors found to db
    print("Updating crawl log info in database...")
    process_crawl_log(db_file, log_path)


    br_png_1 = glob.glob(data_dir + '/*screen.' + br_label + '_1.png')
    br_png_2 = glob.glob(data_dir + '/*screen.' + br_label + '_2.png')
    br_txt_1 = glob.glob(data_dir + '/*source.' + br_label + '_1.txt')
    br_txt_2 = glob.glob(data_dir + '/*source.' + br_label + '_2.txt')
    bot_png_1 = glob.glob(data_dir + '/*screen.' + bot_label + '_1.png')
    bot_png_2 = glob.glob(data_dir + '/*screen.' + bot_label + '_2.png')
    bot_txt_1 = glob.glob(data_dir + '/*source.' + bot_label + '_1.txt')
    bot_txt_2 = glob.glob(data_dir + '/*source.' + bot_label + '_2.txt')

    data_img = {'br': {} , 'bot': {} }
    data_html = {'br': {} , 'bot': {} }

    counter = 0

    print("Iterating each success URL.... " )
    with open(url_file, 'r') as f:
      for line in f:
        bot_png = line.strip()
        h_bot_png = bot_png
        m_http = re.match('^.+:\/\/(.+)',bot_png)
        if (m_http): bot_png = m_http.group(1)
        #print(bot_png + ' -- ' + h_bot_png)
        if h_bot_png not in sites_visited: 
            print("############## " + h_bot_png + " is NOT in sites visited")
            continue
        #print(bot_png)
        #if '1pnews.com' not in bot_png: continue
        #if '163i.com' not in  bot_png: continue
        #if '0aypal.com' not in  bot_png: continue
        #if '2md.com' not in bot_png: continue

        t_bot_png = data_dir + '/' + bot_png
        bot_txt_path_1 = t_bot_png + '.source.' + bot_label + '_1.txt'
        bot_txt_path_2 = t_bot_png + '.source.' + bot_label + '_2.txt'
        br_txt_path_1 =  t_bot_png + '.source.' + br_label + '_1.txt'
        br_txt_path_2 =  t_bot_png + '.source.' + br_label + '_2.txt'

        bot_txt_path_r1 = t_bot_png + '.rendered.' + bot_label + '_1.txt'
        bot_txt_path_r2 = t_bot_png + '.rendered.' + bot_label + '_2.txt'
        br_txt_path_r1 =  t_bot_png + '.rendered.' + br_label + '_1.txt'
        br_txt_path_r2 =  t_bot_png + '.rendered.' + br_label + '_2.txt'

        bot_txt_path_i1 = t_bot_png + '.ifrm.' + bot_label + '_1.txt'
        bot_txt_path_i2 = t_bot_png + '.ifrm.' + bot_label + '_2.txt'
        br_txt_path_i1 =  t_bot_png + '.ifrm.' + br_label + '_1.txt'
        br_txt_path_i2 =  t_bot_png + '.ifrm.' + br_label + '_2.txt'

        bot_txt_path_l1 = t_bot_png + '.links.' + bot_label + '_1.txt'
        bot_txt_path_l2 = t_bot_png + '.links.' + bot_label + '_2.txt'
        br_txt_path_l1 =  t_bot_png + '.links.' + br_label + '_1.txt'
        br_txt_path_l2 =  t_bot_png + '.links.' + br_label + '_2.txt'

        tt_c_png = ""
        m_dc = re.search(r'.+\/(.+)',t_bot_png)
        if (m_dc):
           tt_c_png = m_dc.group(1)

        counter = int(counter) + 1

        print("########### Processing: [" + str(counter) + "] " + tt_c_png + " .......")

        br_img_path_1 = t_bot_png + '.screen.' + br_label + '_1.png'
        bot_img_path_1 = t_bot_png + '.screen.' + bot_label + '_1.png'
        br_img_path_2 = t_bot_png + '.screen.' + br_label + '_2.png'
        bot_img_path_2 = t_bot_png + '.screen.' + bot_label + '_2.png'

        #If the HTML files for 2 consecutive runs for browser and bot are unavailable, IGNORE
        if (not(os.path.isfile(bot_txt_path_1)) or not(os.path.isfile(bot_txt_path_2)) or not(os.path.isfile(br_txt_path_1)) or not(os.path.isfile(br_txt_path_2))):
           print("HTML_FILE_MISSING       " + tt_c_png + '\n')
           continue

        #If the HTML files (RENDERED) for 2 consecutive runs for browser and bot are unavailable, IGNORE
        if (not(os.path.isfile(bot_txt_path_r1)) or not(os.path.isfile(bot_txt_path_r2)) or not(os.path.isfile(br_txt_path_r1)) or not(os.path.isfile(br_txt_path_r2))):
           print("HTML_FILE_MISSING (RENDERED)	" + tt_c_png + '\n')
           continue

        #If the SCREENSHOT files for 2 consecutive runs for browser and bot are unavailable, IGNORE
        if (not(os.path.isfile(bot_img_path_1)) or not(os.path.isfile(bot_img_path_2)) or not(os.path.isfile(br_img_path_1)) or not(os.path.isfile(br_img_path_2))):
           print("SCREENSHOT_FILE_MISSING " + t_bot_png + '\n')
           continue

        #Redirected urls
        br_redirected_init_url = t_bot_png + '.' + br_label + '_1.redirect'
        bot_redirected_init_url = t_bot_png + '.' + bot_label + '_1.redirect'
        br_redirected_url = get_redirected_url(br_redirected_init_url)
        bot_redirected_url = get_redirected_url(bot_redirected_init_url)
        #Ignore if redirected URLs re hosted on top 1-M Alexa domains
        if (br_redirected_url):
           vln_list = is_mal_domain(br_redirected_url)
            
           if is_alexa_domain(str(br_redirected_url)):
               insert_data_to_table(db_file, 'redirects', {'site': h_bot_png, 'redirected_url': str(br_redirected_url), 'client': br_label, 'iter': 1, 'type': 'alexa_domain', 'vuln': vln_list})
               #if vln_list == '[]':
               print("Site hosted on alexa [br]. Skipping... " + h_bot_png)
               continue
           else:
               insert_data_to_table(db_file, 'redirects', {'site': h_bot_png, 'redirected_url': str(br_redirected_url), 'client': br_label, 'iter': 1, 'type': 'other', 'vuln': vln_list})

        if (bot_redirected_url):
           vln_list = is_mal_domain(bot_redirected_url)
           if is_alexa_domain(str(bot_redirected_url)):
               insert_data_to_table(db_file, 'redirects', {'site': h_bot_png, 'redirected_url': str(bot_redirected_url), 'client': bot_label, 'iter': 1, 'type': 'alexa_domain', 'vuln': vln_list})
               #if vln_list == '[]':
               print("Site hosted on alexa [bot]. Skipping... " + h_bot_png)
               continue
           else:
               insert_data_to_table(db_file, 'redirects', {'site': h_bot_png, 'redirected_url': str(bot_redirected_url), 'client': bot_label, 'iter': 1, 'type': 'other', 'vuln': vln_list})


        #If the file size in HTML files for 2 consecutive runs for browser and bot are zero, IGNORE
        #if (os.path.getsize(bot_txt_path_1) == 0 or os.path.getsize(bot_txt_path_2) == 0 or os.path.getsize(br_txt_path_1) == 0 or os.path.getsize(br_txt_path_2) == 0):
        #   f_skip_files.write("ZERO_FILE_SIZE_ZERO	" + t_bot_png + '\n')
        #   continue

        #If the file size in SCREENSHOT files for 2 consecutive runs for browser and bot are zero, IGNORE
        #if (os.path.getsize(bot_img_path_1) == 0 or os.path.getsize(bot_img_path_2) == 0 or os.path.getsize(br_img_path_1) == 0 or os.path.getsize(br_img_path_2) == 0):
        #   f_skip_files.write("SCREENSHOT_FILE_SIZE_ZERO	" + t_bot_png + '\n')
        #   continue

        print("Processing: " + tt_c_png + " - " + str(datetime.datetime.now()) + " .....")


        try:
            if br_txt_path_1 not in data_html['br']: data_html['br'][br_txt_path_1] = get_body_from_html(br_txt_path_r1)
            if bot_txt_path_1 not in data_html['bot']: data_html['bot'][bot_txt_path_1] = get_body_from_html(bot_txt_path_r1)
            if br_txt_path_2 not in data_html['br']: data_html['br'][br_txt_path_2] = get_body_from_html(br_txt_path_r2)
            if bot_txt_path_2 not in data_html['bot']: data_html['bot'][bot_txt_path_2] = get_body_from_html(bot_txt_path_r2)

            #HTML content
            br_txt_content_1 = data_html['br'][br_txt_path_1]['text']
            br_txt_content_2 = data_html['br'][br_txt_path_2]['text']
            bot_txt_content_1 = data_html['bot'][bot_txt_path_1]['text']
            bot_txt_content_2 = data_html['bot'][bot_txt_path_2]['text']

            print("Checking exceptions: " + tt_c_png)
            try:
               if (tt_c_png and is_robot_txt_block(h_bot_png) == False):
                  insert_data_to_table(db_file, 'exceptions', {'site': h_bot_png, 'client': 'N/A', 'iter': 'N/A', 'type': 'robot_txt_not_allowed'})
            except Exception as e:
               insert_data_to_table(db_file, 'exceptions', {'site': h_bot_png, 'client': 'N/A', 'iter': 'N/A', 'type': 'robot_txt_err_check'})
               print("Error checking robots.txt file for " + tt_c_png)
               print(str(e))

            labels_to_chk = ('Too many requests', 'Page cannot be displayed. Please contact your service provider for more details','404 - File or directory not found')

            for l in labels_to_chk:
               if (l in str(br_txt_content_1)):
                  insert_data_to_table(db_file, 'exceptions', {'site': h_bot_png, 'client': br_label, 'iter': 1, 'type': l})
               
               if (l in str(bot_txt_content_1)):
                  insert_data_to_table(db_file, 'exceptions', {'site': h_bot_png, 'client': bot_label, 'iter': 1, 'type': l})
               
               if (l in str(br_txt_content_2)):
                  insert_data_to_table(db_file, 'exceptions', {'site': h_bot_png, 'client': br_label, 'iter': 2, 'type': l})
               
               if (l in str(bot_txt_content_2)):
                  insert_data_to_table(db_file, 'exceptions', {'site': h_bot_png, 'client': bot_label, 'iter': 2, 'type': l})
               
            #Get header meta info
            br_header_1 = get_header_metadata(br_txt_path_1)
            br_header_2 = get_header_metadata(br_txt_path_2)
            bot_header_1 = get_header_metadata(bot_txt_path_1)
            bot_header_2 = get_header_metadata(bot_txt_path_2)
            header_diff_1 = find_header_diff(br_header_1, bot_header_1)
            header_diff_2 = find_header_diff(br_header_2, bot_header_2)
            if header_diff_1 and len(header_diff_1) > 0:
               for k in header_diff_1:
                  if 'br' not in header_diff_1[k]: header_diff_1[k]['br'] = ""
                  if 'bot' not in header_diff_1[k]: header_diff_1[k]['bot'] = ""
                  insert_data_to_table(db_file, 'header_similarity', {'site': h_bot_png, 'iter': 1, 'br_header': header_diff_1[k]['br'].decode('utf-8') , 'bot_header': header_diff_1[k]['bot'].decode('utf-8') , 'type': k})
            if header_diff_2 and len(header_diff_2) > 0:
               for k in header_diff_2:
                  if 'br' not in header_diff_2[k]: header_diff_2[k]['br'] = ""
                  if 'bot' not in header_diff_2[k]: header_diff_2[k]['bot'] = "" 
                  insert_data_to_table(db_file, 'header_similarity', {'site': h_bot_png, 'iter': 2, 'br_header': header_diff_2[k]['br'].decode('utf-8') , 'bot_header': header_diff_2[k]['bot'].decode('utf-8') , 'type': k})

            #Language code
            br_txt_ln_1 = data_html['br'][br_txt_path_1]['ln']
            br_txt_ln_2 = data_html['br'][br_txt_path_2]['ln']
            bot_txt_ln_1 = data_html['bot'][bot_txt_path_1]['ln']
            bot_txt_ln_2 = data_html['bot'][bot_txt_path_2]['ln']
            print("Language detected: [BR_1 -- " + br_txt_ln_1 + "] [BOT_1 -- " + bot_txt_ln_1 + "] [BR_2 -- " + br_txt_ln_2 + "] [BOT_2 -- " + bot_txt_ln_2 + "]")

            bot_html_content_1 = ignore_domain_html(bot_txt_content_1, ignore_pattern)
            br_html_content_1 = ignore_domain_html(br_txt_content_1, ignore_pattern)
            bot_html_content_2 = ignore_domain_html(br_txt_content_2, ignore_pattern)
            br_html_content_2 = ignore_domain_html(br_txt_content_2, ignore_pattern)


            print("Checking domains to be ignored (based on HTML text): " + tt_c_png)
            #Domains to be ignored should exist in both bot and browser
            is_ignore_html_content = 0
            if br_html_content_1 and bot_html_content_1:
                 insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': br_label, 'iter': 1, 'type': 'HTML', 'content': br_txt_content_1.decode('utf-8')})
                 insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': bot_label, 'iter': 1, 'type': 'HTML','content': bot_txt_content_1.decode('utf-8')})
                 is_ignore_html_content = 1

            if br_html_content_2 and bot_html_content_2:
                 insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': br_label, 'iter': 2, 'type': 'HTML', 'content': br_txt_content_2.decode('utf-8')})
                 insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': bot_label, 'iter': 2, 'type': 'HTML', 'content': bot_txt_content_2.decode('utf-8')})
                 is_ignore_html_content = 1

            if is_ignore_html_content: 
               print("Domain marked to be ignored (HTML) --- " + h_bot_png)
               continue

            br_html_data_1 = get_structure_html_text(br_txt_path_1) #data_html['br'][br_txt_path_1]
            bot_html_data_1 = get_structure_html_text(bot_txt_path_1)  #data_html['bot'][bot_txt_path_1]
            br_html_data_2 = get_structure_html_text(br_txt_path_1)  #data_html['br'][br_txt_path_2]
            bot_html_data_2 = get_structure_html_text(bot_txt_path_2)  #data_html['bot'][bot_txt_path_2]
            br_html_data_arr_1 = []
            bot_html_data_arr_1 = []
            br_html_data_arr_2 = []
            bot_html_data_arr_2 = []

            br_html_data_arr_1.extend(br_html_data_1)
            br_html_data_str_1 = br_html_data_arr_1[0] if len(br_html_data_arr_1) else ""
            bot_html_data_arr_1.extend(bot_html_data_1)
            bot_html_data_str_1 = bot_html_data_arr_1[0] if len(bot_html_data_arr_1) else ""
            br_html_data_arr_2.extend(br_html_data_2)
            br_html_data_str_2 = br_html_data_arr_2[0] if len(br_html_data_arr_2) else ""
            bot_html_data_arr_2.extend(bot_html_data_2)
            bot_html_data_str_2 = bot_html_data_arr_2[0] if len(bot_html_data_arr_2) else ""

            #Checks for DYNAMIC web pages - HTML
            br_sim_hash_1 = Simhash(tokenize(br_html_data_str_1))
            br_sim_hash_2 = Simhash(tokenize(br_html_data_str_2))
            bot_sim_hash_1 = Simhash(tokenize(bot_html_data_str_1))
            bot_sim_hash_2 = Simhash(tokenize(bot_html_data_str_2))

            dis_html_bot = abs(bot_sim_hash_1.distance(bot_sim_hash_2))
            dis_html_br = abs(br_sim_hash_1.distance(br_sim_hash_2))
            dis_html_inbetween_1 = abs(br_sim_hash_1.distance(bot_sim_hash_1))
            dis_html_inbetween_2 = abs(br_sim_hash_2.distance(bot_sim_hash_2))

            #print("___________")
            #print(str(dis_html_bot) + ' --- ' + str(bot_html_data_str_1) + ' -- ' + bot_txt_path_1)
            #print(str(dis_html_bot) + ' --- ' + str(bot_html_data_str_2) + ' -- ' + bot_txt_path_2)
            #print(str(dis_html_br) + ' --- ' + str(br_html_data_str_1) + ' -- ' + br_txt_path_1)
            #print(str(dis_html_br) + ' --- ' + str(br_html_data_str_2) + ' -- ' + br_txt_path_2)


            #Process URLs in iframes
            print("Checking iframe document information...")
            if (os.path.isfile(bot_txt_path_i1) and os.path.isfile(bot_txt_path_i2)):
               bot_ifrm_1 = extract_links_from_iframe_docs(bot_txt_path_i1)
               #bot_ifrm_2= extract_links_from_iframe_docs(bot_txt_path_i2)
               for l in bot_ifrm_1:
                   if l is not None:
                      #vln_list = is_mal_domain(l)
                      vln_list = []
                      insert_data_to_table(db_file, 'iframe_links', {'site': h_bot_png, 'client': bot_label, 'iter': 1, 'link': l, 'vuln': json.dumps(vln_list)})

            if (os.path.isfile(br_txt_path_i1) and os.path.isfile(br_txt_path_i2)):
               br_ifrm_1 = extract_links_from_iframe_docs(br_txt_path_i1)
               #br_ifrm_2 = extract_links_from_iframe_docs(br_txt_path_i2)
               for l in br_ifrm_1:
                   if l is not None:
                      #vln_list = is_mal_domain(l)
                      vln_list = []
                      insert_data_to_table(db_file, 'iframe_links', {'site': h_bot_png, 'client': br_label, 'iter': 1, 'link': l, 'vuln': json.dumps(vln_list)})


            #Let's to DYNAMIC PAGE DETECTION LATER
            #if (dis_html_inbetween_1 > dis_html_br and dis_html_inbetween_1 > dis_html_bot and dis_html_inbetween_2 > dis_html_br and dis_html_inbetween_2 > dis_html_bot):
            #   f_domains_to_ignore.write("DYNAMIC_HTML_CONTENT	" + tt_c_png + "\n")
            #   #shutil.copy2(br_txt_path_1, dir_results + '/files_dynamic')
            #   #shutil.copy2(bot_txt_path_1, dir_results + '/files_dynamic')
            #   #shutil.copy2(br_txt_path_2, dir_results + '/files_dynamic')
            #   #shutil.copy2(bot_txt_path_2, dir_results + '/files_dynamic')
            #   write_content_to_file(str(br_txt_content_1), dir_results + '/files_dynamic/' + tt_c_png + '_br_1')
            #   write_content_to_file(str(br_txt_content_2), dir_results + '/files_dynamic/' + tt_c_png + '_br_2')
            #   write_content_to_file(str(bot_txt_content_1), dir_results + '/files_dynamic/' + tt_c_png + '_bot_1')
            #   write_content_to_file(str(bot_txt_content_2), dir_results + '/files_dynamic/' + tt_c_png + '_bot_2')
            #   shutil.copy2(br_img_path_1, dir_results + '/files_dynamic/')
            #   shutil.copy2(br_img_path_2, dir_results + '/files_dynamic/')
            #   shutil.copy2(bot_img_path_1, dir_results + '/files_dynamic/')
            #   shutil.copy2(bot_img_path_2, dir_results + '/files_dynamic/')
            #   continue


            #Ascertain differences in links
            print("Ascertaining differences in links: " + tt_c_png)
            br_links = get_links_from_html(br_txt_path_l1)
            bot_links = get_links_from_html(bot_txt_path_l1)
            links_diff = link_differ(br_links, bot_links)

            if (links_diff): #CHECK SCREENSHOTS?
                is_infected_links_br = 0
                is_infected_links_bot = 0
                links_diff_br = []
                links_diff_bot = []
                if 'br' in links_diff:
                   links_diff_br = links_diff['br']
                if 'bot' in links_diff:
                   links_diff_bot = links_diff['bot']
                
                for link in links_diff_br:
                   #vln_list = is_mal_domain(link)
                   vln_list = []
                   if vln_list: is_infected_links_br = 1
                   insert_data_to_table(db_file, 'link_dissimilarity', {'site': h_bot_png, 'client': br_label, 'iter': 1, 'link': link, 'vuln': json.dumps(vln_list), 'content': br_txt_content_1.decode('utf-8')})

                for link in links_diff_bot:
                   #vln_list = is_mal_domain(link)
                   vln_list = []
                   if vln_list: is_infected_links_bot = 1
                   
                   insert_data_to_table(db_file, 'link_dissimilarity', {'site': h_bot_png, 'client': bot_label, 'iter': 1, 'link': link, 'vuln': json.dumps(vln_list), 'content': bot_txt_content_1.decode('utf-8')})


            #Jaccard Index - Element similarity - POSSIBLE CLOAKING (CONTINUE)
            print("Checking element similarity: " + tt_c_png)
            jaccard_score = jaccard_similarity_custom(br_links,bot_links)
            if (1-abs(jaccard_score) < 0.2):
               shutil.copy2(br_img_path_1, dir_results + '/ele_diff/')
               shutil.copy2(bot_img_path_1, dir_results + '/ele_diff/')
               write_content_to_file(str(br_txt_content_1), dir_results + '/ele_diff/' + tt_c_png + '_br_1')
               write_content_to_file(str(bot_txt_content_1), dir_results + '/ele_diff/' + tt_c_png + '_bot_1')

               #print("POSSIBLE CLOAKING (ELEMENT DISSIMILARITY --- " + h_bot_png)
            insert_data_to_table(db_file, 'jac_similarity', {'site': h_bot_png, 'score': abs(jaccard_score),  'br_content': br_txt_content_1.decode('utf-8'), 'bot_content': bot_txt_content_1.decode('utf-8')})
               #continue


            #Sim hash - content similarity
            print("Checking content similarity: " + tt_c_png)
            simhash_h_distance_1 = br_sim_hash_1.distance(bot_sim_hash_1)
            simhash_h_distance_2 = br_sim_hash_2.distance(bot_sim_hash_2)
            simhash_h_distance_br = br_sim_hash_1.distance(br_sim_hash_2)
            simhash_h_distance_bot = bot_sim_hash_1.distance(bot_sim_hash_2)

            if (abs(simhash_h_distance_1) > 10): #POSSIBLE CLOAKING (CONTINUE)
               shutil.copy2(br_img_path_1, dir_results + '/content_diff/')
               shutil.copy2(bot_img_path_1, dir_results + '/content_diff/')
               write_content_to_file(str(br_txt_content_1), dir_results + '/content_diff/' + tt_c_png + '_br_1')
               write_content_to_file(str(bot_txt_content_1), dir_results + '/content_diff/' + tt_c_png + '_bot_1')
 
               #if  abs(simhash_h_distance_1) > 0: print("@@@@@@@@@@@@@@@@@@@@@@@@ " + str(abs(simhash_h_distance_1)))

               #print("POSSIBLE CLOAKING (PAGE CONTENT DISSIMILARITY --- " + h_bot_png)
               #print("--- CONTENT -- " + str(abs(simhash_h_distance_br)) + ' -- ' + str( abs(simhash_h_distance_bot)) + ' --- ' + str(abs(simhash_h_distance_1)) + ' -- ' + str(abs(simhash_h_distance_2)))
            insert_data_to_table(db_file, 'content_similarity', {'site': h_bot_png, 'h_bt_br': abs(simhash_h_distance_br), 'h_bt_bot': abs(simhash_h_distance_bot), 'h_bt_one' : abs(simhash_h_distance_1), 'h_bt_two': abs(simhash_h_distance_2),  'score': abs(simhash_h_distance_1), 'br_content': br_txt_content_1.decode('utf-8'), 'bot_content': bot_txt_content_1.decode('utf-8')})

            #Check for TOPIC similarity
            br_topic = gen_lda(br_txt_content_1.decode('utf-8')) if br_txt_content_1 else ""
            br_topic_1 = br_topic['t1']['name'] if br_topic else ""
            br_topic_2 = br_topic['t2']['name'] if br_topic else ""
            br_topic_3 = br_topic['t3']['name'] if br_topic else ""
            br_prob_1 = br_topic['t1']['val'] if br_topic else ""
            br_prob_2 = br_topic['t2']['val'] if br_topic else ""
            br_prob_3 = br_topic['t3']['val'] if br_topic else ""

            bot_topic = gen_lda(bot_txt_content_1.decode('utf-8')) if bot_txt_content_1 else ""
            bot_topic_1 = bot_topic['t1']['name'] if bot_topic else ""
            bot_topic_2 = bot_topic['t2']['name'] if bot_topic else ""
            bot_topic_3 = bot_topic['t3']['name'] if bot_topic else ""
            bot_prob_1 = bot_topic['t1']['val'] if bot_topic else ""
            bot_prob_2 = bot_topic['t2']['val'] if bot_topic else ""
            bot_prob_3 = bot_topic['t3']['val'] if bot_topic else ""
            
            is_topics_same = 1 if (br_topic_1 and br_topic_2 and br_topic_3 and bot_topic_1 and bot_topic_2 and bot_topic_3 and br_topic_1 == bot_topic_1 and br_topic_2 == bot_topic_2 and br_topic_3 == bot_topic_3) else 0
            print("Checking TOPIC similarity: [BR_TOPIC -- " + br_topic_1 + ',' + br_topic_2 + ',' + br_topic_3 + "] [BOT_TOPIC -- " + bot_topic_1 + "," + bot_topic_2 + ',' + bot_topic_3 +  "] [MATCHED -- " + str(is_topics_same) + "]")

            insert_data_to_table(db_file, 'topic_similarity', {'site': h_bot_png,  'br_topic_1': br_topic_1, 'br_topic_2': br_topic_2, 'br_topic_3': br_topic_3, 'bot_topic_1': bot_topic_1, 'bot_topic_2': bot_topic_2, 'bot_topic_3': bot_topic_3 ,  'br_prob_1': str(br_prob_1), 'br_prob_2': str(br_prob_2), 'br_prob_3': str(br_prob_3), 'bot_prob_1': str(bot_prob_1), 'bot_prob_2': str(bot_prob_2), 'bot_prob_3': str(bot_prob_3), 'matched': is_topics_same})


            #Check for dynamic content (based on screenshots)
            br_img_hash_1 = get_image_hash(br_img_path_1)
            bot_img_hash_1 = get_image_hash(bot_img_path_1)
            br_img_hash_2 = get_image_hash(br_img_path_2)
            bot_img_hash_2 = get_image_hash(bot_img_path_2)

            #Checks for DYNAMIC web pages - SS
            dis_ss_bot = abs(bot_img_hash_1-bot_img_hash_2)
            dis_ss_br = abs(br_img_hash_1-br_img_hash_2)
            dis_ss_inbetween_1 = abs(br_img_hash_1-bot_img_hash_1)
            dis_ss_inbetween_2 = abs(br_img_hash_2-bot_img_hash_2)
           
            #For DYNAMIC content - Uncomment Image Similarity later
            #if not (dis_ss_inbetween_1 > dis_ss_br and dis_ss_inbetween_1 > dis_ss_bot and dis_ss_inbetween_2 > dis_ss_br and dis_ss_inbetween_2 > dis_ss_bot):
            #   f_domains_to_ignore.write("DYNAMIC_IMG_CONTENT	" + tt_c_png + "\n")
            #   shutil.copy2(br_img_path_1, dir_results + '/files_dynamic')
            #   shutil.copy2(bot_img_path_1, dir_results + '/files_dynamic')
            #   shutil.copy2(br_img_path_2, dir_results + '/files_dynamic')
            #   shutil.copy2(bot_img_path_2, dir_results + '/files_dynamic')
            #   write_content_to_file(str(br_txt_content_1), dir_results + '/files_dynamic/' + tt_c_png + '_br_1')
            #   write_content_to_file(str(br_txt_content_2), dir_results + '/files_dynamic/' + tt_c_png + '_br_2')
            #   write_content_to_file(str(bot_txt_content_1), dir_results + '/files_dynamic/' + tt_c_png + '_bot_1')
            #   write_content_to_file(str(bot_txt_content_2), dir_results + '/files_dynamic/' + tt_c_png + '_bot_2')
            #   continue

            #If the image contains non-English text (browser or bot), to reduce processing time. The language of the image is determined by HTML source language
            #If the language is not determined, we treat it as English (LIMITATION) 
            is_img_en = 0
            if not (br_txt_ln_1 == 'en' or bot_txt_ln_1 == 'en'): 
               ln_str = br_txt_ln_1
               if not ln_str: ln_str = bot_txt_ln_1
               print("Non-english page from checking Image similaity: " + tt_c_png)
               insert_data_to_table(db_file, 'non_english_sites', {'site': h_bot_png, 'lang_br': br_txt_ln_1, 'lang_bot': bot_txt_ln_1})
            else:
               is_img_en = 1

            #Image OCR processing (only if image content is in English)
            br_img_text_raw_1 = "[NULL]"
            bot_img_text_raw_1 = "[NULL]"
            br_img_text_raw_2 = "[NULL]"
            bot_img_text_raw_2 = "[NULL]"

            if (is_img_en):
               print("Processing OCR for screenshots....")
               br_img_text_raw_1 = image_to_text_raw(br_img_path_1, br_txt_ln_1)
               bot_img_text_raw_1 = image_to_text_raw(bot_img_path_1, bot_txt_ln_1)
               br_img_text_raw_2 = image_to_text_raw(br_img_path_2, br_txt_ln_2)
               bot_img_text_raw_2 = image_to_text_raw(bot_img_path_2, bot_txt_ln_2)

               br_img_text_1 = image_to_text(br_img_text_raw_1)
               bot_img_text_1 = image_to_text(bot_img_text_raw_1)
               br_img_text_2 = image_to_text(br_img_text_raw_2)
               bot_img_text_2 = image_to_text(bot_img_text_raw_2)

               bot_img_content_1 = ignore_domain_img(str(bot_img_text_raw_1), ignore_pattern)
               br_img_content_1 = ignore_domain_img(str(br_img_text_raw_1), ignore_pattern)
               bot_img_content_2 = ignore_domain_img(str(bot_img_text_raw_2), ignore_pattern)
               br_img_content_2 = ignore_domain_img(str(br_img_text_raw_2), ignore_pattern)

               print("Checking domains to be ignored (based on image text): " + tt_c_png)
               is_ignore_domain = 0
               if br_img_content_1:
                    br_img_content_1 = br_img_content_1.decode('utf-8')
                    insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': br_label, 'iter': 1, 'type': 'IMG',  'content': br_img_content_1})
                    is_ignore_domain = 1
               if bot_img_content_1:
                    bot_img_content_1 = bot_img_content_1.decode('utf-8')
                    insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': bot_label, 'iter': 1, 'type': 'IMG', 'content': bot_img_content_1})
                    is_ignore_domain = 1
               if br_img_content_2:
                    br_img_content_2 = br_img_content_2.decode('utf-8')
                    insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': br_label, 'iter': 2, 'type': 'IMG', 'content': br_img_content_2})
                    is_ignore_domain = 1
               if bot_img_content_1:
                    bot_img_content_2 = bot_img_content_2.decode('utf-8')
                    insert_data_to_table(db_file, 'domains_ignored', {'site': h_bot_png, 'client': bot_label, 'iter': 2, 'type': 'IMG', 'content': bot_img_content_2})
                    is_ignore_domain = 1
               if is_ignore_domain: 
                  print("Domain marked to be ignored (IMG) --- " + h_bot_png)
                  continue


            #Image hash - screenshot similarity -- #POSSIBLE CLOAKING (CONTINUE)
            print("Checking image similarity: " + tt_c_png)
            distance_img_1 = bot_img_hash_1 - br_img_hash_1
            distance_img_2 = bot_img_hash_2 - br_img_hash_2
            distance_img_br = br_img_hash_1 - br_img_hash_2
            distance_img_bot = bot_img_hash_1 - bot_img_hash_2

            #If there is a discrepancy in number of links, OR number of links in pages differ, consider as cloaking
            bot_img_text_raw_str_1 = ""
            br_img_text_raw_str_1 = ""
            if (abs(distance_img_1) > 20):
               shutil.copy2(br_img_path_1, dir_results + '/img_diff/')
               shutil.copy2(bot_img_path_1, dir_results + '/img_diff/')
               shutil.copy2(br_txt_path_1, dir_results + '/img_diff/')
               shutil.copy2(bot_txt_path_1, dir_results + '/img_diff/')
               write_content_to_file(str(br_txt_content_1), dir_results + '/img_diff/' + tt_c_png + '_br')
               write_content_to_file(str(bot_txt_content_1), dir_results + '/img_diff/' + tt_c_png + '_bot')

               br_img_text_raw_str_1 = ""
               bot_img_text_raw_str_1 = ""
               try:
                  br_img_text_raw_str_1 = str(br_img_text_raw_1)
               except NameError:
                  br_img_text_raw_str_1 = ""
               try:
                  bot_img_text_raw_str_1 = str(bot_img_text_raw_1)
               except NameError:
                  bot_img_text_raw_str_1 = ""

               #bot_img_text_raw_str_1 = str(bot_img_text_raw_1)

               br_img_text_raw_1 = image_to_text_raw(br_img_path_1, br_txt_ln_1)
               bot_img_text_raw_1 = image_to_text_raw(bot_img_path_1, bot_txt_ln_1)

               #br_img_text_1 = image_to_text(br_img_text_raw_1)
               #bot_img_text_1 = image_to_text(bot_img_text_raw_1)
               #br_img_text_raw_str_1 = str(br_img_text_1)
               #bot_img_text_raw_str_1 = str(bot_img_text_1)
               br_img_text_raw_str_1 = str(br_img_text_raw_1)
               bot_img_text_raw_str_1 = str(bot_img_text_raw_1)

               try:
                  br_img_text_raw_str_1 = br_img_text_raw_str_1.decode('utf-8')
               except Exception as e:
                  br_img_text_raw_str_1 = ""

               try:
                  bot_img_text_raw_str_1 = bot_img_text_raw_str_1.decode('utf-8')
               except Exception as e:
                  bot_img_text_raw_str_1 = ""

               #if br_img_text_raw_str_1 is None or not br_img_text_raw_str_1: br_img_text_raw_str_1 = ""
               #if bot_img_text_raw_str_1 is None or not bot_img_text_raw_str_1: bot_img_text_raw_str_1 = ""
            insert_data_to_table(db_file, 'image_similarity', {'site': h_bot_png, 'h_bt_br': abs(distance_img_br), 'h_bt_bot': abs(distance_img_bot), 'h_bt_one': abs(distance_img_1), 'h_bt_two': abs(distance_img_2),  'score': abs(distance_img_1), 'br_content': br_img_text_raw_str_1, 'bot_content': bot_img_text_raw_str_1})
               #print("POSSIBLE CLOAKING (IMG DISSIMILARITY --- " + h_bot_png)
               #continue


        except Exception as e:
           print("ERROR OCCURED: " + str(e))
           print('-'*60)
           traceback.print_exc(file=sys.stdout)
           print('-'*60)

           continue


