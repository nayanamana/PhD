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


if __name__=="__main__":
    model_file = '/mnt/extra1/projects/phishing/scripts_m2/model/model.pkl'
    #model_file = '/mnt/extra1/projects/phishing/scripts_m2/model/gb_model_210.pkl'

    option = 1 

    if option == 0:
       ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p.pkl'
       bn_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'

       leg = pd.read_pickle(bn_data_file)
       phish = pd.read_pickle(ph_data_file)

       pd.set_option('display.max_rows', 10000)
       pd.set_option('display.max_columns', 10000)
       np.set_printoptions(threshold=10000)
        
       feat_vect = pd.concat([leg,phish],ignore_index=True)
       feat_vect = feat_vect.fillna(0)

       features = feat_vect.columns
       features = features.drop(["start_url","label"])

       build_model_ex(feat_vect,features,model_file)

    #---------------------------------------------

    if option == 1:
       ph_data_file_test = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_misc.pkl'
       #bn_data_file_test = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_misc.pkl'
       phish_test = pd.read_pickle(ph_data_file_test)
       #bn_test = pd.read_pickle(bn_data_file_test)

       pd.set_option('display.max_rows', 10000)
       pd.set_option('display.max_columns', 10000)
       np.set_printoptions(threshold=10000)

       #feat_vect_test = pd.concat([leg_test,phish_test],ignore_index=True)
       #feat_vect_test = pd.concat([phish_test,bn_test],ignore_index=True)
       feat_vect_test = pd.concat([phish_test],ignore_index=True)
       feat_vect_test = feat_vect_test.fillna(0)

       features_test = feat_vect_test.columns
       features_test = features_test.drop(["start_url","label"])
    
       predict_model_ex(feat_vect_test,features_test,model_file)

    #----------------------------------
