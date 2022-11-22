#!/usr/local/bin/python3.8


#Ref: https://pypi.org/project/google-play-scraper/
#Ref: https://github.com/facundoolano/google-play-scraper
import warnings

import gensim

warnings.filterwarnings('ignore')
import os
import sys
import csv
import json
import numpy as np
import play_scraper

try:
  import spacy
except Exception as e:
  import spacy

from sklearn.feature_extraction.text import TfidfVectorizer

from google_play_scraper import app

# Import and download stopwords from NLTK.
from nltk.corpus import stopwords
from nltk import download, word_tokenize, sent_tokenize, WordNetLemmatizer
from sklearn.metrics.pairwise import cosine_similarity
import spacy

from google_trans_new import google_translator

#download('stopwords')  # Download stopwords list.
#stop_words = stopwords.words('english')

'''
#------------
import gensim.downloader as api

from gensim.similarities import SparseTermSimilarityMatrix
from gensim.similarities import WordEmbeddingSimilarityIndex
from gensim import corpora

#Ref: https://github.com/RaRe-Technologies/gensim/blob/develop/docs/notebooks/soft_cosine_tutorial.ipynb
stop_words = stopwords.words('english')
w2v_model = api.load("glove-wiki-gigaword-50")
similarity_index = WordEmbeddingSimilarityIndex(w2v_model)
#similarity_matrix = SparseTermSimilarityMatrix(similarity_index, dictionary)
#--------------
'''
#from semantic_compare import SemanticComparator as sc

#Ref: https://stackoverflow.com/questions/36936914/list-of-android-permissions-normal-permissions-and-dangerous-permissions-in-api
#dangerous_perm = ["READ_CALENDAR","WRITE_CALENDAR","CAMERA","READ_CONTACTS","WRITE_CONTACTS","GET_ACCOUNTS",
#"ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","RECORD_AUDIO","READ_PHONE_STATE","READ_PHONE_NUMBERS","CALL_PHONE",
#"ANSWER_PHONE_CALLS","READ_CALL_LOG","WRITE_CALL_LOG","ADD_VOICEMAIL","USE_SIP","PROCESS_OUTGOING_CALLS",
#"BODY_SENSORS","SEND_SMS","RECEIVE_SMS","READ_SMS","RECEIVE_WAP_PUSH","RECEIVE_MMS",
#"READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","ACCESS_MEDIA_LOCATION",
#"ACCEPT_HANDOVER","ACCESS_BACKGROUND_LOCATION","ACTIVITY_RECOGNITION"]

#Ref: https://spacy.io/models/en#en_core_web_md
#nlp = spacy.load('en_core_web_lg')
#nlp = spacy.load('en_core_web_md')

def extract_dangerous_perm(perm):
    global dangerous_perm

    perm_json = {}

    try:
        perm = perm.replace("'", '"')
        perm_json = json.loads(perm)
    except Exception as e:
        #print(perm)
        #print(str(e))
        pass

    perm_res = []
    perm_keys = perm_json.keys()
    #print(list(perm_keys))
    for p in perm_keys:
        p_tokens = p.split('.')
        if len(p_tokens) > 0:
            tail_perm = p_tokens[-1]
            if tail_perm in dangerous_perm:
                perm_res.append(tail_perm)
    perm_res = sorted(perm_res)
    return perm_res

def get_merged_perm_tokens(perm_list):
    token_dict_res = {}

    for p in perm_list:
        p = p.lower()
        p_split = p.split('_')
        p_merged = ' '.join(p_split)
        if p_merged not in token_dict_res: token_dict_res[p_merged] = 1
        #for t in p_split:
        #    if t not in token_dict_res:
        #        token_dict_res[t.lower()] = 1
    token_dict_res = sorted(token_dict_res)
    return token_dict_res

def get_app_details(apk_name):
    # get app details
    result_apk = app(
        apk_name,
        lang='en',  # defaults to 'en'
        country='us'  # defaults to 'us'
    )
    return result_apk

def process_desc(text):
    global stop_words
    text_list = [w.lower() for w in word_tokenize(text)]
    #print(text_list)
    text_list_proc = []

    for w in text_list:
        if w in stop_words: continue
        if not w.isalpha(): continue
        w = WordNetLemmatizer().lemmatize(w, 'v')
        text_list_proc.append(w.strip())

    doc_str = ' '.join(text_list_proc)
    return doc_str

#Ref: https://datascience.stackexchange.com/questions/66471/pre-trained-python-package-for-semantic-word-similarity
def eval_semantic_similarity(desc, perm):
     res_dict = {'perm': {}, 'max_sim': 0}
     desc_proc = process_desc(desc)

     desc_nlp = nlp(desc)
     sem_sim_list = []
     for p in perm:
        if p == "": continue
        p_nlp = nlp(p)
        sem_sim = desc_nlp.similarity(p_nlp)
        res_dict['perm'][p.replace(' ','_').upper()] = sem_sim
        sem_sim_list.append(sem_sim)
     res_dict['max_sim'] = max(sem_sim_list) if len(sem_sim_list) > 0 else 0
     #res_str = json.dumps(res_dict)
     #print(res_str)
     #return res_str
     return res_dict

def google_translate(text):
   t_text = text
   if not text or text == "": return text
   try:
      translator = google_translator() 
      t_text = translator.translate(text)
   except:
      pass
   return t_text

#Ref: https://github.com/danieliu/play-scraper
#Ref: https://pypi.org/project/play-scraper/
def get_trending_apps():
   #apps = play_scraper.categories()
   apps = play_scraper.search('trending', page=2)
   print(apps)
   

def input_data():
    #get_trending_apps()
    
    in_file = "/tmp/top_free_apps"
    out_list = []

    counter = 0
    with open(in_file, encoding="utf8") as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            out_data = {}

            #if len(row) != 4: continue
            counter += 1
            print("Processing app # " + str(counter))
            #print(len(row))
            #apk_name = row[1]
            app_name = row[0]
            #perm = row[3]
            #d_perm = extract_dangerous_perm(perm) #list of dangerous permissions

            out_data['app_name'] = app_name

            try:
              apk_details = get_app_details(app_name)
              if apk_details:
                out_data['installs'] = apk_details['installs']
                out_data['ratings'] = apk_details['ratings']
                out_data['reviews'] = apk_details['reviews']
                out_data['android_version'] = apk_details['androidVersion']
                out_data['developer'] = apk_details['developer']
                out_data['developer_email'] = apk_details['developerEmail']
                out_data['developer_website'] = apk_details['developerWebsite']
                out_data['genre'] = apk_details['genre']
                out_data['ad_supported'] = apk_details['adSupported']
                out_data['contains_ads'] = apk_details['containsAds']
                out_data['url'] = apk_details['url']
                out_data['privacy_policy'] = apk_details['privacyPolicy']
                out_data['title'] = apk_details['title']
                out_data['description'] = apk_details['description']
                if out_data['description']: out_data['description'] = google_translate(out_data['description'].replace('\r\n',''))
            except Exception as e:
                continue

            #merged_perm_tokens = get_merged_perm_tokens(d_perm)
            #out_data['d_perm'] = d_perm
            #res_sem_sim = eval_semantic_similarity(out_data['description'], merged_perm_tokens)
            #out_data['sem_sim_perm'] = res_sem_sim['perm']
            #out_data['max_sem_sim_perm'] = res_sem_sim['max_sim']

            tmp_out_data = out_data
            #del tmp_out_data['description']
            out_list.append(tmp_out_data)

            #print(out_data)
            #break

    #print(out_list)
    keys = out_list[0].keys()
    out_file = "/tmp/top_free_apps_out.csv"
    with open(out_file, 'w+', newline='')  as output_file:
       dict_writer = csv.DictWriter(output_file, keys)
       dict_writer.writeheader()
       dict_writer.writerows(out_list)
    #print(counter)

def main():
    data = input_data()


if __name__ == '__main__':
    main()
