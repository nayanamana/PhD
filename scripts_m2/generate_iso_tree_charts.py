#!/usr/local/bin/python3.8

import warnings
warnings.filterwarnings('ignore')

import sys, os, json
import subprocess
import traceback

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import csv
import sys,os
import subprocess
import dns
from bs4 import BeautifulSoup as beatsop
import os.path

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

#Disable warnings
pd.options.mode.chained_assignment = None  # default='warn'

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

from sklearn import decomposition
from sklearn.preprocessing import StandardScaler

import pickle
import urllib.request

from urllib.parse import urlparse
from threading import Thread
#import sys
import queue
import urllib.request

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import build_feat_vect

#----------------------------------
from sklearn.ensemble import IsolationForest

import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from mpl_toolkits.mplot3d import Axes3D

#----------------------------------------

# importing libaries ----
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pylab import savefig
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import build_model

# default plot settings
plt.rcParams['figure.dpi'] = 300
plt.rcParams['figure.figsize'] = [15, 10]


def extract_features(dirname, data_path):
   #res =  build_feat_vect.build_feature_vector(dirname, model_dir + '/fvm.pkl')
   res =  build_feat_vect.build_feature_vector(dirname, data_path)
   #print(res)
   return res

def gen_scatter_plots():
  #out_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_sources_p'
  out_dir = '/mnt/extra1/projects/phishing/scripts_m2/ph_updated_src'
  #phish_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/phishing_1'
  #benign_file = '/mnt/extra1/projects/phishing/scripts_m2/url_lists/benign_1'

  model_dir = '/mnt/extra1/projects/phishing/scripts_m2/processed_data'
  #extract_features(out_dir, model_dir + '/proc_data_p.pkl')
  #--------------
  ####ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p.pkl'
  ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_misc.pkl'

  phish = pd.read_pickle(ph_data_file)
  print(phish)

  X_phish = phish.drop(columns=['start_url', 'label'])
  print(X_phish)

  Y_phish = phish.label
  print(Y_phish)

  start_url_df_phish = phish.start_url
  print(start_url_df_phish)

  #----------------------------------------
  '''
  plt.title("Outlier Inspection")
  p1 = plt.scatter(start_url_df,Y, c='white',
                 s=20*4, edgecolor='k')

  plt.axis('tight')
  plt.xlim((-2, 5))
  plt.ylim((-2, 5))
  plt.legend([p1],
           ["training observations"
            ],
           loc="lower right")

  # saving the figure
  plt.savefig('outlier_inspection.png', dpi=300)
  '''

  #Ref: https://towardsdatascience.com/anomaly-detection-with-isolation-forest-visualization-23cd75c281e2
  print("#########################################")
  clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12), \
                        max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, verbose=0)
  clf.fit(X_phish)

  pred_phish = clf.predict(X_phish)
  X_phish['anomaly']=pred_phish
  outliers_phish=X_phish.loc[X_phish['anomaly']==-1]
  outlier_phish_index= X_phish.index #list(start_url_df_phish)
  #print(outlier_index)
  #Find the number of anomalies and normal points here points classified -1 are anomalous
  print(X_phish['anomaly'].value_counts())

  #--------------------------------

  '''
  pca = PCA(n_components=3)  # Reduce to k=3 dimensions
  scaler = StandardScaler()
  #normalize the metrics
  X = scaler.fit_transform(X_phish)
  X_reduce = pca.fit_transform(X)
  fig = plt.figure()
  ax = fig.add_subplot(111, projection='3d')
  ax.set_zlabel("x_composite_3")
  # Plot the compressed data points
  ax.scatter(X_reduce[:, 0], X_reduce[:, 1], zs=X_reduce[:, 2], s=4, lw=1, label="inliers",c="green")
  # Plot x's for the ground truth outliers
  ax.scatter(X_reduce[outlier_phish_index,0],X_reduce[outlier_phish_index,1], X_reduce[outlier_phish_index,2],
#           lw=2, s=60, marker="x", c="red", label="outliers")
           lw=1, s=4, marker="x", c="red", label="outliers")

  ax.legend()
  plt.savefig('outlier_pca_3d', dpi=300)
  '''

  '''
  #--------------------------
  pca = PCA(2)
  pca.fit(X_phish)
  res=pd.DataFrame(pca.transform(X_phish))
  Z = np.array(res)
  plt.title("IsolationForest")
  plt.contourf( Z, cmap=plt.cm.Blues_r)
  b1 = plt.scatter(res[0], res[1], c='green',
                 s=20,label="normal points")
  b1 =plt.scatter(res.iloc[outlier_phish_index,0],res.iloc[outlier_phish_index,1], c='green',s=20,  edgecolor="red",label="predicted outliers")
  plt.legend(loc="upper right")
  plt.savefig('outlier_pca_2d', dpi=300)

  #--------------------------------------------
  '''

  #--------------------------
  ph_orig_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p.pkl'
  ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'
  leg_orig_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'
  leg_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
  newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_misc.pkl'

  phish = pd.read_pickle(ph_data_file)
  phish_orig = pd.read_pickle(ph_orig_data_file)
  phish = pd.concat([phish,phish_orig],ignore_index=True)

  X_phish = phish.drop(columns=['start_url', 'label'])
  Y_phish = phish.label
  start_url_df_phish = phish.start_url

  leg = pd.read_pickle(leg_data_file)
  leg_orig = pd.read_pickle(leg_orig_data_file)
  leg = pd.concat([leg,leg_orig],ignore_index=True)

  X_leg = leg.drop(columns=['start_url', 'label'])
  Y_leg = leg.label
  start_url_df_leg = leg.start_url

  newdom = pd.read_pickle(newdom_data_file)
  X_newdom = newdom.drop(columns=['start_url', 'label'])
  Y_newdom = newdom.label
  start_url_df_newdom = newdom.start_url

  pca_phish = PCA(2)
  pca_phish.fit(X_phish)
  res_phish=pd.DataFrame(pca_phish.transform(X_phish))
  Z_phish = np.array(res_phish)
  plt.title("IsolationForest")
  #plt.contourf( Z_phish, cmap=plt.cm.Blues_r)

  p1 = plt.scatter(res_phish[0], res_phish[1], c='red',
                 s=20,label="phishtank points")

  pca_leg = PCA(2)
  pca_leg.fit(X_leg)
  res_leg=pd.DataFrame(pca_leg.transform(X_leg))
  Z_leg = np.array(res_leg)

  l1 = plt.scatter(res_leg[0], res_leg[1], c='green',
                 s=20,label="legitimate points")

  pca_newdom = PCA(2)
  pca_newdom.fit(X_newdom)
  res_newdom=pd.DataFrame(pca_newdom.transform(X_newdom))
  Z_newdom = np.array(res_newdom)

  n1 = plt.scatter(res_newdom[0], res_newdom[1], c='blue',
                 s=20,label="new domains points")



  #b1 =plt.scatter(res.iloc[outlier_phish_index,0],res.iloc[outlier_phish_index,1], c='green',s=20,  edgecolor="red",label="predicted outliers")
  plt.legend(loc="upper right")
  plt.savefig('outlier_pca_pln', dpi=300)

  #--------------------------------------------

def model_isolation_trees(phish, newdom):
  #ph_orig_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p.pkl'
  #ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'
  #ph_orig_data_file = ph_data_file
  #leg_orig_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'
  #leg_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_misc.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'

  #phish = pd.read_pickle(ph_data_file)
  #phish_orig = pd.read_pickle(ph_orig_data_file)
  #phish = pd.concat([phish_orig],ignore_index=True)
  X_phish = phish.drop(columns=['start_url', 'label'])
  Y_phish = phish.label
  start_url_df_phish = phish.start_url

  #newdom = pd.read_pickle(newdom_data_file)
  #newdom = pd.concat([newdom],ignore_index=True)
  tmp_newdom = newdom
  X_newdom = newdom.drop(columns=['start_url', 'label'])
  Y_newdom = newdom.label
  start_url_df_newdom = newdom.start_url

  #Ref: https://towardsdatascience.com/anomaly-detection-with-isolation-forest-visualization-23cd75c281e2
  #print("#########################################")
  #clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12), \
  #contamination_coof = float(0.3)
  contamination_coof = float(0.12)
  #contamination_coof = 'auto'
  clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=contamination_coof, \
                        #max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, verbose=0)
                        max_features=1.0, bootstrap=False, n_jobs=-1, random_state=None, verbose=0)
 
  clf.fit(X_phish)

  pred_newdom = clf.predict(X_newdom)
  print("isolation forest")
  print(pred_newdom)
 

  '''
  #Ref: https://towardsdatascience.com/anomaly-detection-with-isolation-forest-visualization-23cd75c281e2
  no_comp = 40
  #print(X_newdom.shape)
  pca = PCA(no_comp)
  scaler = StandardScaler()
  X_newdom1 = scaler.fit_transform(X_newdom)
  X_newdom_reduced = pca.fit_transform(X_newdom1)
  
  print(X_newdom_reduced.shape)
  clf.fit(X_newdom_reduced)
  #pred_newdom = clf.predict(X_newdom)
  pred_newdom = clf.predict(X_newdom_reduced)
  '''
 
  #----------------------------

  X_newdom['anomaly']=pred_newdom
  #Find the number of anomalies and normal points here points classified -1 are anomalous
  anomaly_value_counts = X_newdom['anomaly'].value_counts()
  print(anomaly_value_counts)
  non_outliers_set=X_newdom.loc[X_newdom['anomaly']==1]
  outliers_set=X_newdom.loc[X_newdom['anomaly']==-1]

  #non_anomalous (i.e., phishing) urls
  non_anomalous_urls = []
  non_anomalous_ind = []
  for ind in non_outliers_set.index:
     non_anomaly_url = start_url_df_newdom[ind]
     non_anomalous_urls.append(non_anomaly_url)
     non_anomalous_ind.append(ind)
     #print(non_anomaly_url) 
     #print(non_outliers_set[ind])

  print('------------------------')
  print("Anomolous URLs")
  for ind in outliers_set.index:
     anomaly_url = start_url_df_newdom[ind]
     print(anomaly_url)

  anomalous_ind = []
  for ind in outliers_set.index:
     anomalous_ind.append(ind)

  #print(non_anomalous_ind)
  #for ind in non_anomalous_ind:
  #   print(ind)
  #   print(tmp_newdom.index[ind])
  #   print('----------------------------')
  tmp_newdom.drop(tmp_newdom.index[anomalous_ind], inplace=True)
  #print("----------------------------")
  print("zzzz")
  print(tmp_newdom.shape)
  #print(tmp_newdom)

  return tmp_newdom
  
def build_model_ex(train,features,model_file):
    build_model.build_gb(train,features, model_file)

def predict_model_ex(train,features,model_file):
    build_model.predict_gb(train,features,model_file)

def main():
  ph_orig_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p.pkl'
  ph_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'
  #ph_orig_data_file = ph_data_file
  leg_orig_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'
  leg_newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_newdom.pkl'
  leg_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
  newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_util.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_misc.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_b_test.pkl'
  #newdom_data_file = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_test.pkl'
  newdom_data_file1 = '/mnt/extra1/projects/phishing/scripts_m2/processed_data/proc_data_p_misc.pkl'


  model_file = '/mnt/extra1/projects/phishing/scripts_m2/model/gb_stacked_model.pkl'

  phish_orig = pd.read_pickle(ph_orig_data_file)
  phish = pd.concat([phish_orig],ignore_index=True)

  leg =  pd.read_pickle(leg_orig_data_file)
  leg_newdom =  pd.read_pickle(leg_newdom_data_file)

  newdom = pd.read_pickle(newdom_data_file)
  newdom1 = pd.read_pickle(newdom_data_file1)

  #newdom = pd.concat([newdom, newdom1],ignore_index=True)

  #Isolation trees
  #gen_scatter_plots()
  #filtered_data_isol_trees = model_isolation_trees(phish, newdom)
  filtered_data_isol_trees = model_isolation_trees(newdom, newdom)

  if filtered_data_isol_trees.shape[0] == 0:
     print("**** Length of data frame is zero")
     return 
  
  return #REMOVE
  #Gradient Boosting
  #-- build model --
  feat_vect = pd.concat([leg,leg_newdom,phish_orig],ignore_index=True)
  #feat_vect = pd.concat([leg,phish_orig],ignore_index=True)
  feat_vect = feat_vect.fillna(0)

  features = feat_vect.columns
  features = features.drop(["start_url","label"])

  #REMOVE COMMENT BELOW TO BUILD MODEL
  ####build_model_ex(feat_vect,features,model_file)

  #--- predict --
  feat_vect_test = pd.concat([filtered_data_isol_trees],ignore_index=True)
  feat_vect_test = feat_vect_test.fillna(0)

  features_test = feat_vect_test.columns
  features_test = features_test.drop(["start_url","label"])

  predict_model_ex(feat_vect_test,features_test,model_file)
 


### MAIN ###
if __name__ == "__main__":
    main()

