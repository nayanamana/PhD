#!/usr/local/bin/python3.8

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import csv
import sys,os,getopt
import subprocess
import traceback
import random
import itertools
import json

from datetime import datetime,timedelta
import time
from datetime import timezone

import mysql.connector
from mysql.connector import Error

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
from sklearn.inspection import permutation_importance
from sklearn.preprocessing import StandardScaler

#Ref: https://machinelearningmastery.com/roc-curves-and-precision-recall-curves-for-classification-in-python/
#from sklearn.metrics import roc_curve
#from sklearn.metrics import roc_auc_score
from sklearn.metrics import precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import f1_score
from sklearn.metrics import auc
#from matplotlib import pyplot
from sklearn.feature_selection import chi2

from sklearn.preprocessing import LabelEncoder
import imblearn
from imblearn.over_sampling import SMOTE

from boruta import BorutaPy

import pickle

from scipy.stats import chisquare
from sklearn.utils import resample


#Ref: https://elitedatascience.com/imbalanced-classes
def downsample_majority_class(df):
   '''
   # Separate majority and minority classes
   df_majority = df[df.is_phish==False]
   df_minority = df[df.is_phish==True]
 
   # Downsample majority class
   df_majority_downsampled = resample(df_majority, 
                                 replace=False,    # sample without replacement
                                 n_samples=len(df_majority),     # to match minority class
                                 random_state=123) # reproducible results
 
   # Combine minority class with downsampled majority class
   df_downsampled = pd.concat([df_majority_downsampled, df_minority])
 
   # Display new class counts
   print(df_downsampled.is_phish.value_counts())
   return df_downsampled
   '''
   minority = df[df["is_phish"] == True]
   try:
      df = (df.groupby('is_phish', as_index=False)
        .apply(lambda x: x.sample(n=len(minority)))
        .reset_index(drop=True))
   except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

      minority = df[df["is_phish"] == False]
      df = (df.groupby('is_phish', as_index=False)
        .apply(lambda x: x.sample(n=len(minority)))
        .reset_index(drop=True))

   return df

def print_column_names(df):
   print(df.columns.tolist())
   print('-------------------------------------')

def print_column_names_with_given_value(df, val):
   #print(df.columns[(df.loc[df.index == no].values==val)[0]])
   print("####### Column names with a given value (" + str(val) + ") #######")
   i, c = np.where(df == val)
   result = df[df==val].any()
   print(result)

def print_column_names_with_na_values(df):
   print("####### Column names with NaN values #######")
   print(df.isna().any())

def print_column_data_types(df):
   print(df.dtypes)

def drop_unwanted_columns(df):
  df.drop("w_time_since_dom_reg", axis=1, inplace=True)
  df.drop("w_time_to_dom_exp", axis=1, inplace=True)
  df.drop("w_is_whois_privacy", axis=1, inplace=True)
  df.drop("w_dnssec", axis=1, inplace=True)
  df.drop("w_time_since_dom_update", axis=1, inplace=True)
  df.drop("c_has_expired_certs", axis=1, inplace=True)
  df.drop("s_forms_with_empty_actions", axis=1, inplace=True)
  #df.drop("has_suspicious_tld_in_domain", axis=1, inplace=True)
  #df.drop("has_tlds_in_sub_domain", axis=1, inplace=True)
  #df.drop("number_of_hyphens_in_domain", axis=1, inplace=True)
  df.drop("d_number_of_subdomains", axis=1, inplace=True)

  df.drop('Unnamed: 0', axis=1, inplace=True)
  df.drop("domain", axis=1, inplace=True)
  df.drop("url", axis=1, inplace=True)

  #df.drop("w_ns_asn", axis=1, inplace=True)

  return df

def update_nan_columns(df):
  df["w_registrar"].fillna("other",  inplace = True)
  df["w_ns_geo"].fillna("other",  inplace = True)
  df["w_ns_asn"].fillna("other",  inplace = True)
  df["w_registrant_org"].fillna("other",  inplace = True)
  df["w_registrant_country"].fillna("other",  inplace = True)
  df["c_cert_issuer_name"].fillna("other",  inplace = True)
  df["c_cert_issuer_country"].fillna("other",  inplace = True)

  return df

#Ref: https://stackoverflow.com/questions/41472951/using-regex-matched-groups-in-pandas-dataframe-replace-function
def update_rows_with_comma(df):
   #df = df[~df.w_ns_asn.str.contains(",")]
   #df = df[df['w_ns_asn'].str.contains(',', case=False), 'w_ns_asn'] = '0'
   df.w_ns_asn = df.w_ns_asn.astype(str)
   df.w_ns_asn = df.w_ns_asn.str.replace(r'.*,.*', '0', regex=True)
   #df.w_ns_asn = df.w_ns_asn.str.replace({r'(\d+),.*' : r'\1'}, regex=True)
   df.w_ns_asn = df.w_ns_asn.astype(str)
   #df = df.w_ns_asn.replace({r'(\d+),.+' : r'\1'}, regex=True)
   return df

def clean_data(df, is_down_sample):
  print("--------- Column names -------------")
  print_column_names(df)

  #Drop unwanted columns
  df = drop_unwanted_columns(df)

  #df.drop("dnssec", axis=1, inplace=True)
  #df.drop("time_since_dom_update", axis=1, inplace=True)
  #df.drop("has_expired_certs", axis=1, inplace=True)
  #To eleminate NaN corr
  #df.drop("is_whois_privacy", axis=1, inplace=True)
  #df.drop("has_tlds_in_sub_domain", axis=1, inplace=True)
  #df.drop("no_of_consecutive_characters", axis=1, inplace=True)

  #df.drop("cert_lifespan", axis=1, inplace=True)
  #df.drop("cert_issuer_name", axis=1, inplace=True)
  #df.drop('cert_issuer_country', axis=1, inplace=True)

  #Replace values
  ###df["is_cert_issued_from_free_ca"] = df["is_cert_issued_from_free_ca"].astype(int).replace(-1, 0)

  #Remove columns having a specific ocolumn value. i.e., -1 in ns field
  df = df[df.w_ns != ""]

  #Replace invalid values
  #bool_conv = {"True": 1, "False": 0, "-1": 0}
  #df["registrar"] = df["registrar"].astype(str).replace(-1, 'nodata')
  #df["ns_sld"] = df["ns_sld"].astype(str).replace(-1, 'nodata')
  #df["ns_geo"] = df["ns_geo"].astype(str).replace(-1, 'nodata')
  #df["ns_asn"] = df["ns_asn"].astype(str).replace(-1, 'nodata')
  #df["registrant_org"] = df["registrant_org"].astype(str).replace(-1, 'nodata')
  #df["registrant_country"] = df["registrant_country"].astype(str).replace(-1, 'nodata')
  #df["domain_life_span"] = df["domain_life_span"].astype(int).replace(-1, 0)
  #df["number_of_hyphens_in_sub_domain"] = df["number_of_hyphens_in_sub_domain"].astype(int).replace(-1, 0)
  #df["is_domain_resolves"] = df["is_domain_resolves"].astype(str).replace("False",0).replace("True",1).replace("-1",0).astype(int)
  #df["cert_lifespan"] = df["cert_lifespan"].astype(int).replace(-1, 0)
  #df["cert_issuer_name"] = df["cert_issuer_name"].astype(str).replace("-1", "nodata")
  #df["cert_issuer_name"] = df["cert_issuer_name"].astype(str).replace(-1, "nodata")
  #df["cert_issuer_country"] = df["cert_issuer_country"].astype(str).replace("-1", "nodata") 
  #df["is_cert_issued_from_free_ca"] = df["is_cert_issued_from_free_ca"].astype(int).replace(-1, 0)
  #df["no_of_sub_domains"] = df["no_of_sub_domains"].astype(int).replace(-1, 0)

  print("----------- Target counts ----------------")
  print(df["is_phish"].value_counts())

  #Update NaN values
  df = update_nan_columns(df)
  #df["ns"].fillna("other",  inplace = True)
  #df["ns_sld"].fillna("other",  inplace = True)
  #df["ns_asn"].fillna("other",  inplace = True)
  #df["registrant_org"].fillna("other",  inplace = True) #CHANGE
  #df["registrant_country"].fillna("other",  inplace = True)
  #df["domain_life_span"].fillna(0,  inplace = True)

  #Update integer true/false to booleans
  #df["is_phish"] = df["is_phish"].astype(bool)
  df = update_rows_with_comma(df)

  #-----------------
  ''' 
  df.drop('domain_life_span', axis=1, inplace=True)
  df.drop('min_lev_distance', axis=1, inplace=True)
  df.drop('shannon_entropy', axis=1, inplace=True)
  df.drop('number_of_digits', axis=1, inplace=True)
  
  df.drop('registrant_org', axis=1, inplace=True)
  
  df.drop('registrant_country', axis=1, inplace=True)
  df.drop('registrar', axis=1, inplace=True)
  #df.drop('ns', axis=1, inplace=True)

  df.drop('ns_sld', axis=1, inplace=True)
  
  df.drop('ns_asn', axis=1, inplace=True)
  ''' 

  #df = df[df["registrant_org"] != "-1"]
  #df = df[df["registrar"] != "-1"]  
  #df = df[df["ns"] != "-1"]
  #df = df[df["ns_sld"] != "-1"]
  #df = df[df["ns_asn"] != "-1"]
  #df = df[df["registrant_country"] != "-1"]

  #Remove rows that has -1 in any column value
  #df = df[(df != -1).all(1)]
  df = df[(df != "-1" ).all(axis=1)]

  #Remove rows with Nan values in "ns" column
  df = df[df['w_ns'].notna()]

  #balance the data - https://stackoverflow.com/questions/52935324/make-dataframe-balanced-with-respect-to-a-specific-column
  #Ref: https://dev.to/lberlin/balancing-the-imbalanced-2bgo
  
  #print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
  #print(df["is_phish"].value_counts())
  #print('-----------------------------')  

  ####print("####### Column names with a given value (-1) #######")
  #print_column_names_with_given_value(df, "-1")
  ######print_column_names_with_given_value(df, "-1")

  if is_down_sample: df = downsample_majority_class(df)
  print("----------- Target counts ----------------")
  print(df["is_phish"].value_counts())

  #print_column_names_with_na_values(df)
  #print(print_column_data_types(df))

  #Dropping columns reported as weak by Boruta
  #df.drop('no_of_sub_domains', axis=1, inplace=True)
  #df.drop('has_suspicious_tld_in_domain', axis=1, inplace=True)
  #df.drop('number_of_hyphens_in_sub_domain', axis=1, inplace=True)
  #df.drop('number_of_digits', axis=1, inplace=True)
  #df.drop('ns_geo', axis=1, inplace=True)
  #df.drop('is_cert_issued_from_free_ca', axis=1, inplace=True)

  #df.drop('time_since_dom_reg', axis=1, inplace=True)
  #df.drop('time_to_dom_exp', axis=1, inplace=True)

  #Dropping fields giving a low corr
  #df.drop('is_domain_resolves', axis=1, inplace=True)
  #df.drop('number_of_hyphens_in_sub_domain', axis=1, inplace=True)
  #df.drop('domain_length', axis=1, inplace=True)

  #drop remaining rows with null values
  ###df = df.dropna()

  #print(df["registrar"].values.tolist())
  ###print(df.dtypes)
  ###print("*********************************")
  ###print(df.describe().T)
  ###print('------------------------------')
  #print(df[df.isnull().any(axis=1)])
  #print('------------------------------')

  return df


