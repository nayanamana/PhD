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

from boruta import BorutaPy

import pickle

from scipy.stats import chisquare

def clean_data(df):
  #Drop unwanted columns
  df.drop('Unnamed: 0', axis=1, inplace=True)
  df.drop("domain", axis=1, inplace=True)
  df.drop("dnssec", axis=1, inplace=True)
  df.drop("time_since_dom_update", axis=1, inplace=True)
  df.drop("has_expired_certs", axis=1, inplace=True)
  #To eleminate NaN corr
  df.drop("is_whois_privacy", axis=1, inplace=True)
  df.drop("has_tlds_in_sub_domain", axis=1, inplace=True)

  #Dopping certificate data
  df.drop("ns_asn", axis=1, inplace=True)
  df.drop("registrant_country", axis=1, inplace=True)
  df.drop("min_lev_distance", axis=1, inplace=True)
  df.drop("shannon_entropy", axis=1, inplace=True)
  df.drop("domain_length", axis=1, inplace=True)
  df.drop("no_of_consecutive_characters", axis=1, inplace=True)

  df.drop("cert_lifespan", axis=1, inplace=True)
  df.drop("cert_issuer_name", axis=1, inplace=True)
  df.drop("cert_issuer_country", axis=1, inplace=True)

  #Replace values
  df["is_cert_issued_from_free_ca"] = df["is_cert_issued_from_free_ca"].astype(int).replace(-1, 0)
  df["number_of_hyphens_in_sub_domain"] = df["number_of_hyphens_in_sub_domain"].astype(int).replace(-1, 0)
  ###df["cert_lifespan"] = df["cert_lifespan"].astype(int).replace(-1, 0)
  ###df["cert_issuer_name"] = df["cert_issuer_name"].astype(str).replace('-1', 'nodata')
  ###df["cert_issuer_country"] = df["cert_issuer_country"].astype(str).replace('-1', 'nodata')
  #df["shannon_entropy"] = (df["shannon_entropy"]*10000).astype(int)

  #Remove rows that has -1 in any column value
  df = df[(df != -1).all(1)]

  #print(df.loc[6,:])
  ###df["is_whois_privacy"] = df["is_whois_privacy"].astype(bool)

  
  '''
  #Format categorical data
  le = LabelEncoder()
  #Ref: https://stackoverflow.com/questions/46406720/labelencoder-typeerror-not-supported-between-instances-of-float-and-str
  df["registrar"] = le.fit_transform(df["registrar"].astype(str))
  df["ns"] = le.fit_transform(df["ns"].astype(str))
  df["ns_sld"] = le.fit_transform(df["ns_sld"].astype(str))
  df["ns_geo"] = le.fit_transform(df["ns_geo"].astype(str))
  df["registrant_org"] = le.fit_transform(df["registrant_org"].astype(str))
  df["registrant_country"] = le.fit_transform(df["registrant_country"].astype(str))
  
  df["ns_asn"] = le.fit_transform(df["ns_asn"].astype(str))
  df["cert_issuer_name"] = le.fit_transform(df["cert_issuer_name"].astype(str))
  df["cert_issuer_country"] = le.fit_transform(df["cert_issuer_country"].astype(str))
  '''

  #df["registrar"] = df["registrar"].value_counts(normalize=True).mul(1000000).round(0)
  #df["registrar"] = df["registrar"].count()
  #df["registrar"] = len(df["registrar"])

  #Update NaN values
  df["registrar"].fillna("other",  inplace = True)
  df["ns"].fillna("other",  inplace = True)
  df["ns_sld"].fillna("other",  inplace = True)
  ###df["ns_asn"].fillna("other",  inplace = True)
  df["registrant_org"].fillna("other",  inplace = True)
  #df["registrant_country"].fillna("other",  inplace = True)
  ###df["cert_issuer_name"].fillna("other",  inplace = True)
  ###df["cert_issuer_country"].fillna("other",  inplace = True)

  #Update integer true/false to booleans
  df["is_phish"] = df["is_phish"].astype(bool)

  #Drop coorelation (pearson) of > 0.05 from dataframe
  #has_suspicious_tld_in_domain       0.020990
  #no_of_sub_domains                  0.018093
  #number_of_hyphens_in_sub_domain    0.018061
  #registrant_country                 0.011443
  #number_of_digits                  -0.005179
  '''
  df.drop('has_suspicious_tld_in_domain', axis=1, inplace=True)
  df.drop('no_of_sub_domains', axis=1, inplace=True)
  df.drop('number_of_hyphens_in_sub_domain', axis=1, inplace=True)
  df.drop('registrant_country', axis=1, inplace=True)
  df.drop('number_of_digits', axis=1, inplace=True)
  '''

  #Dropping columns reported as weak by Boruta

  df.drop('no_of_sub_domains', axis=1, inplace=True)
  df.drop('has_suspicious_tld_in_domain', axis=1, inplace=True)
  df.drop('number_of_hyphens_in_sub_domain', axis=1, inplace=True)
  df.drop('number_of_digits', axis=1, inplace=True)
  df.drop('ns_geo', axis=1, inplace=True)
  df.drop('is_cert_issued_from_free_ca', axis=1, inplace=True)

  #tmp drop
  #df.drop('registrar', axis=1, inplace=True)
  '''
  df.drop('registrant_org', axis=1, inplace=True)
  df.drop('is_cert_issued_from_free_ca', axis=1, inplace=True)
  df.drop('ns_geo', axis=1, inplace=True)
  df.drop('cert_issuer_name', axis=1, inplace=True)
  df.drop('ns', axis=1, inplace=True)
  df.drop('is_domain_resolves', axis=1, inplace=True)
  df.drop('registrant_country', axis=1, inplace=True)
  df.drop('cert_issuer_country', axis=1, inplace=True)
  '''

  #print(df["registrar"].values.tolist())
  print(df.dtypes)

  return df

