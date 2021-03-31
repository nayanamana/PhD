#!/usr/local/bin/python3.8

import sys,statistics

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn import metrics
import pandas as pd
import numpy as np
import pickle
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import build_model

def build_model_ex(train,features,model_file):
    build_model.build_gb(train,features, model_file)

def predict_model_ex(train,features,model_file):
    build_model.predict_gb(train,features,model_file)

def pred(model_file):
    f = open(model_file,'rb')
    model = pickle.load(f)
    f.close()

    ph_data_file_test = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'
    bn_data_file_test = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
    phish_test = pd.read_pickle(ph_data_file_test)
    bn_test = pd.read_pickle(bn_data_file_test)

    for item in phish_test:
       #print(phish_test[item])
       item_val = phish_test[item]
       print(item_val)
       break



if __name__=="__main__":
    model_file = '/mnt/extra1/projects/phishing/scripts_m2/model/model.pkl'

    option =  1

    if option == 0:
       ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p.pkl'
       bn_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'
       bn_data_tranco_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_tranco.pkl'
       leg_newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_newdom.pkl'

       leg = pd.read_pickle(bn_data_file)
       leg_tranco = pd.read_pickle(bn_data_tranco_file)
       leg_newdom =  pd.read_pickle(leg_newdom_data_file)
       
       phish = pd.read_pickle(ph_data_file)

       pd.set_option('display.max_rows', 10000)
       pd.set_option('display.max_columns', 10000)
       np.set_printoptions(threshold=10000)

       '''
       print("eee")
       print(leg.shape)
       print(leg_newdom.shape)
       print(phish.shape)
       '''

        
       feat_vect = pd.concat([leg,leg_newdom, leg_tranco,phish],ignore_index=True)
       #feat_vect = pd.concat([leg,phish],ignore_index=True)
       feat_vect = feat_vect.fillna(0)

       features = feat_vect.columns
       features = features.drop(["start_url","label"])

       build_model_ex(feat_vect,features,model_file)

    #---------------------------------------------

    if option == 1:
       '''
       ph_data_file_test = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'
       bn_data_file_test = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
       newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_misc.pkl'
       cira_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_cira.pkl'
       util_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_util.pkl'
       nd2203_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_nd2203.pkl'

       phish_test = pd.read_pickle(ph_data_file_test)
       bn_test = pd.read_pickle(bn_data_file_test)
       leg_newdom =  pd.read_pickle(newdom_data_file)
       leg_cira =  pd.read_pickle(cira_data_file)
       util =  pd.read_pickle(util_data_file)
       nd2203 = pd.read_pickle(nd2203_data_file)
       #nd2203 = nd2203.drop_duplicates()
       '''

       newdom_file = '/mnt/extra2/web_domains/workspace/ph_sources/fea_vec/fea_vec_26032021.pkl'
       newdom = pd.read_pickle(newdom_file)

       pd.set_option('display.max_rows', 10000)
       pd.set_option('display.max_columns', 10000)
       np.set_printoptions(threshold=10000)

       #feat_vect_test = pd.concat([leg_test,phish_test],ignore_index=True)
       #feat_vect_test = pd.concat([phish_test,bn_test,leg_newdom],ignore_index=True)
       #feat_vect_test = pd.concat([util],ignore_index=True)
       #feat_vect_test = pd.concat([leg_cira],ignore_index=True)
       feat_vect_test = pd.concat([newdom],ignore_index=True)
       feat_vect_test = feat_vect_test.fillna(0)

       features_test = feat_vect_test.columns
       features_test = features_test.drop(["start_url","label"])
    
       #predict_model_ex(feat_vect_test,features_test,model_file)

       build_model.predict_urls(newdom, model_file)

    #----------------------------------
    #pred(model_file)
