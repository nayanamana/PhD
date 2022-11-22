#!/usr/local/bin/python3.8

#Ref: https://pypi.org/project/google-play-scraper/
#Ref: https://github.com/facundoolano/google-play-scraper
import warnings

import gensim

#from check_keywords import check_keywords

warnings.filterwarnings('ignore')
import os
import sys
import csv
import json
import numpy as np

import scipy
from sklearn.feature_extraction.text import TfidfVectorizer

from google_play_scraper import app

# Import and download stopwords from NLTK.
from nltk.corpus import stopwords
from nltk import download, word_tokenize, sent_tokenize, WordNetLemmatizer
from sklearn.metrics.pairwise import cosine_similarity

download('stopwords')  # Download stopwords list.
stop_words = stopwords.words('english')

#from semantic_compare import SemanticComparator as sc

#Ref: https://stackoverflow.com/questions/36936914/list-of-android-permissions-normal-permissions-and-dangerous-permissions-in-api
dangerous_perm = ["READ_CALENDAR","WRITE_CALENDAR","CAMERA","READ_CONTACTS","WRITE_CONTACTS","GET_ACCOUNTS",
"ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","RECORD_AUDIO","READ_PHONE_STATE","READ_PHONE_NUMBERS","CALL_PHONE",
"ANSWER_PHONE_CALLS","READ_CALL_LOG","WRITE_CALL_LOG","ADD_VOICEMAIL","USE_SIP","PROCESS_OUTGOING_CALLS",
"BODY_SENSORS","SEND_SMS","RECEIVE_SMS","READ_SMS","RECEIVE_WAP_PUSH","RECEIVE_MMS",
"READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","ACCESS_MEDIA_LOCATION",
"ACCEPT_HANDOVER","ACCESS_BACKGROUND_LOCATION","ACTIVITY_RECOGNITION"]

class NumpyEncoder(json.JSONEncoder):
    """ Special json encoder for numpy types """
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return json.JSONEncoder.default(self, obj)


def extract_dangerous_perm(perm):
    global dangerous_perm

    perm_json = {}

    try:
        perm = perm.replace("'", '"')
        perm_json = json.loads(perm)
    except Exception as e:
        pass

    perm_res = []
    perm_keys = perm_json.keys()
    for p in perm_keys:
        p_tokens = p.split('.')
        if len(p_tokens) > 0:
            tail_perm = p_tokens[-1]
            if tail_perm in dangerous_perm:
                perm_res.append(tail_perm)
    perm_res = sorted(perm_res)
    #return perm_res

def get_merged_perm_tokens(perm_list):
    token_dict_res = {}

    if perm_list is None: return token_dict_res
    for p in perm_list:
        p = p.lower()
        p_split = p.split('_')
        p_merged = ' '.join(p_split)
        if p_merged not in token_dict_res: token_dict_res[p_merged] = 1
    token_dict_res = sorted(token_dict_res)
    return token_dict_res

def get_app_details(apk_name):
    result_apk = app(
        apk_name,
        lang='en',  # defaults to 'en'
        country='us'  # defaults to 'us'
    )
    return result_apk

#Ref: https://pypi.org/project/semantic-compare/
#Ref: try this - https://dev.to/coderasha/compare-documents-similarity-using-python-nlp-4odp
def compare_phrases(desc, perm):
    #print(desc)
    #desc = "This is my location where I stay.  I stay in mount lavinia."
    desc_docs = sent_tokenize(desc)
    gen_docs = [[w.lower() for w in word_tokenize(text)]
            for text in desc_docs]

    dictionary = gensim.corpora.Dictionary(gen_docs)
    #print(dictionary.token2id)
    corpus = [dictionary.doc2bow(gen_doc) for gen_doc in gen_docs]
    #print(corpus)
    tf_idf = gensim.models.TfidfModel(corpus)
    for doc in tf_idf[corpus]:
        print([[dictionary[id], np.around(freq, decimals=2)] for id, freq in doc])

    #create similarity measure object
    sim_measure_dir = "/tmp/sim_measure"
    sims = gensim.similarities.Similarity(sim_measure_dir, tf_idf[corpus],
                                          num_features=len(dictionary))
    #print(sims)

    #----------------------------------------
    #Create query document
    perm_docs = []
    for p in perm:
        tokens = sent_tokenize(p)
        for line in tokens:
            perm_docs.append(line)
    for line in perm_docs:
       query_doc = [w.lower() for w in word_tokenize(line)]
       print(query_doc)
       query_doc_bow =  dictionary.doc2bow(query_doc)
       print(query_doc_bow)
    #print(perm)


    print('-------------------')
    pass

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

#Ref: https://blog.christianperone.com/2013/09/machine-learning-cosine-similarity-for-vector-space-models-part-iii/
def eval_cosine_sim(desc, perm):
    desc_proc= process_desc(desc)

    documents = [desc_proc]
    for p in perm:
      documents.append(p)
    #documents.append("this is my location")

    tfidf_vectorizer = TfidfVectorizer()
    tfidf_matrix = tfidf_vectorizer.fit_transform(documents)
    res_cosign_sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix)
    #print(res_cosign_sim)
    return res_cosign_sim

def input_data():
    in_file = "/tmp/dangerous_permission.txt"
    out_data = {}

    counter = 0
    with open(in_file, encoding="utf8") as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            if len(row) != 4: continue
            counter += 1
            #print(len(row))
            apk_name = row[1]
            app_name = row[2]
            perm = row[3]
            d_perm = extract_dangerous_perm(perm) #list of dangerous permissions
            out_data['merged_perm_tokens'] = get_merged_perm_tokens(d_perm)

            out_data['app_name'] = app_name
            out_data['d_perm'] = d_perm

            apk_details = get_app_details(app_name)
            cosign_sim= []
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
                out_data['title'] = apk_details['title']
                out_data['description'] = apk_details['description']
                if out_data['description']: out_data['description'] = out_data['description'].replace('\r\n','')
 
    cosign_sim = eval_cosine_sim(out_data['description'], out_data['merged_perm_tokens'])
    if 'cosign_sim' not in out_data: out_data['cosign_sim'] = json.dumps(cosign_sim, cls=NumpyEncoder)

    print(out_data)
            #break
    #print(counter)

def main():
    data = input_data()


if __name__ == '__main__':
    main()
