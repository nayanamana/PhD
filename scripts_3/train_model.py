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
from sklearn.decomposition import PCA

#Ref: https://machinelearningmastery.com/roc-curves-and-precision-recall-curves-for-classification-in-python/
#from sklearn.metrics import roc_curve
#from sklearn.metrics import roc_auc_score
from sklearn import metrics
from sklearn.metrics import precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import f1_score
from sklearn.metrics import auc
#from matplotlib import pyplot
from sklearn.feature_selection import chi2

from sklearn.preprocessing import LabelEncoder

from sklearn.cluster import KMeans

from boruta import BorutaPy

import pickle

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
from ml_fn import *

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

#Disable warnings
pd.options.mode.chained_assignment = None  # default='warn'

mysql_user = 'root'
mysql_pwd = 'mysql'

db_create_sql_file = '/mnt/extra1/projects/phishing/scripts_3/prediction_stats.sql'


data_path = '/mnt/extra1/projects/phishing/data/heuristics.csv'
model_dir = '/mnt/extra1/projects/phishing/models_is_phish'

time_yesterday = datetime.now().timestamp() - 60*60*24 #REMOVE
date_yesterday = time.strftime('%d%m%Y', time.localtime(time_yesterday))
#date_yesterday='24092020'
#date_yesterday = '04102020'

def get_dt_with_delta(date_str, delta):
   start = datetime.strptime(date_str, "%d%m%Y") #string to date
   end = start - timedelta(days=delta) # date - days
   end_str = end.strftime("%d%m%Y")
   return end_str

def print_column_names(df):
   print(df.columns.tolist())
   print('-------------------------------------')

def connect_result():
    """ Connect to MySQL database """
    #print("Connecting to mysql database [cs_cert_results]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='cs_cert_results',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            #print('Connected to MySQL database')
            return conn

    except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def remove_duplicates_from_list(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]

#if os.path.exists(data_path):
#  os.remove(data_path)

def init():
  if os.path.exists(data_path):
     os.remove(data_path)

#dt_delta = 7

#Create model directory if not exists
  if not os.path.exists(model_dir):
     os.makedirs(model_dir)

def create_db():
   global pghost
   global db
   global postgres_user
   global db_create_sql_file

   print("Creating database/tables (if not exist)")

   cmd = '/usr/bin/mysql -u ' + mysql_user + ' -p' + mysql_pwd + ' < ' + db_create_sql_file
   print("Running command => " + cmd)
   output = subprocess.getoutput(cmd)
   print(output)
   #print('-------------------------------------')

def connect_result():
    """ Connect to MySQL database """
    #print("Connecting to mysql database [cs_cert_results]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            #print('Connected to MySQL database')
            return conn

    except Exception as e:
      print(str(e))
      traceback.print_exc(file=sys.stdout)

def save_data_as_csv():
  conn = connect_result()
  cursor = conn.cursor()
  #cursor.execute("select domain, is_phish, heuristics from heuristics where is_phish=1")
  cursor.execute("select domain, url, is_phish, heuristics from heuristics where is_phish=1")

  res_list_phish = []
  result_phish = cursor.fetchall()
  for d in result_phish: res_list_phish.append(d)

  phish_count = len(result_phish)

  cursor.execute("select domain, url, is_phish, heuristics from heuristics where is_phish=0 limit " + str(phish_count))

  res_list_ben = []
  result_ben = cursor.fetchall()
  for d in result_ben: res_list_ben.append(d)

  print("## Number of phishing domains: " + str(len(result_phish)))
  print("## Number of benign domains: " + str(len(result_ben)))

  res_list = []
  res_list.extend(res_list_phish)
  res_list.extend(res_list_ben)

  field_list = ['domain', 'url', 'is_phish']
  for d in res_list:
     heuristics = json.loads(d[3])
     field_list.extend(heuristics.keys()) 
     break

  f_res_list = []

  for d in res_list:
     domain_name = d[0]
     url = d[1]
     is_phish = d[2]
     ###heuristics = d[3]

     #CHECK
     #print(d[3])
     #if isinstance(d[3], int) and d[2] == -1:
     #    continue
     #if isinstance(d[3], bool):
     #    continue

     heuristics = json.loads(d[3])

     #if 'w_ns_asn' in heuristics and ',' in heuristics['w_ns_asn']:
     #   tmp_list = heuristics['w_ns_asn'].split(',')
     #   heuristics['w_ns_asn'] = tmp_list[0]

     h_arr = [domain_name,url,is_phish]
     for f_item in field_list:
        if f_item == 'domain' or f_item == 'url' or f_item == 'is_phish': continue
        h_item = heuristics[f_item]
        #if isinstance(h_item, list):
        #     h_item = ':'.join(h_item)
        if isinstance(h_item, str):
             h_item = h_item.lower()
        if isinstance(h_item, str) and '[' in h_item and ']' in h_item:
           try:
              h_item_t = json.loads(h_item)
              if isinstance(h_item_t, list):
                 if len(h_item_t) == 1:
                    h_item_t = h_item_t[0]
                 else:
                    h_item_t.sort()
                    h_item_t = ':'.join(str(i) for i in h_item_t)
                 h_item = h_item_t
           except Exception as e:
              pass
        h_arr.append(h_item)
     f_res_list.append(h_arr)

  #print(field_list)
  print("saving dataframe to: " + data_path)
  df = pd.DataFrame(f_res_list)
  df.to_csv(data_path, header=field_list)


def load_data(csv_path):
 return pd.read_csv(csv_path, error_bad_lines=False)

def zero_fields(df):
  print(df.isin([0]).sum())

def nan_fields(df):
  print(df.isnull().sum(axis = 0))

def value_counts_of_field(df, field):
   print(df[field].value_counts(dropna=False))

def uniq_vals(df, field):
   print(df[field].unique())

def data_types(df):
  print(df.dtypes) 

def save_model(model, mtype):
  #Save model to file
  #Ref: https://stackabuse.com/scikit-learn-save-and-restore-models/
  pkl_filename = model_dir + '/pickle_model_' + mtype + '.pkl'
  print("### MODEL PATH: " + model_dir + '/pickle_model_' + mtype + '.pkl')
  with open(pkl_filename, 'wb') as file:
     pickle.dump(model, file)

def load_model(mtype):
  #Load model from file
  #Ref: https://stackabuse.com/scikit-learn-save-and-restore-models/
  pkl_filename = model_dir + '/pickle_model_' + mtype + '.pkl'
  with open(pkl_filename, 'rb') as file:
     pickle_model = pickle.load(file)
     return pickle_model

def histogram_intersection(a, b):
    v = np.minimum(a, b).sum().round(decimals=1)
    return v

def do_corr(df, target):
   #REF: https://datascience.stackexchange.com/questions/39137/how-can-i-check-the-correlation-between-features-and-target-variable
   #corr_matrix = df.corr()
   #print(corr_matrix[target].sort_values(ascending=False))

   ''''
   print('--------------------------------------')
   #Ref: https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.corr.html
   print('Pearson correlation')
   cp_matrix = df[df.columns[0:]].corr(method='pearson')[target][:].sort_values(ascending=False)
   print(cp_matrix)
   print('--------------------------------------')
   print('Kendall correlation')
   ck_matrix = df[df.columns[0:]].corr(method='kendall')[target][:].sort_values(ascending=False)
   print(ck_matrix)
   print('--------------------------------------')
   print('Spearman correlation')
   cs_matrix = df[df.columns[0:]].corr(method='spearman')[target][:].sort_values(ascending=False)
   print(cs_matrix)
   print('--------------------------------------')
   print('Histogram intersection')
   hist_int = df.corr(method=histogram_intersection)
   print(hist_int)
   print('--------------------------------------')

   #Ref: https://stackoverflow.com/questions/17778394/list-highest-correlation-pairs-from-a-large-correlation-matrix-in-pandas
   kot = corr_matrix[corr_matrix>=.9]
   plt.figure(figsize=(12,8))
   sns.heatmap(kot, cmap="Greens")
   plt.savefig("corr_out.png")

   #Ref: https://www.tutorialspoint.com/machine_learning_with_python/machine_learning_with_python_correlation_matrix_plot.htm
   no_of_features = 14 #CHECK
   names = df.columns
   fig = plt.figure()
   ax = fig.add_subplot(111)
   cax = ax.matshow(corr_matrix, vmin=-1, vmax=1)
   fig.colorbar(cax)
   ticks = np.arange(0,no_of_features,1)
   ax.set_xticks(ticks)
   ax.set_yticks(ticks)
   ax.set_xticklabels(names, rotation='vertical', size = 8)
   ax.set_yticklabels(names, size = 8)
   #pyplot.show()
   plt.autoscale()
   plt.savefig("corr_out1.png", bbox_inches = "tight")
   '''
   

   print('-------------------------------------------------')
   print("Corelation - Pearson")
   no_of_features = 14 #CHECK
   out = df.apply(lambda x : pd.factorize(x)[0]).corr(method='pearson', min_periods=1)

   #Ref: https://stackoverflow.com/questions/38913965/make-the-size-of-a-heatmap-bigger-with-seaborn
   fig, ax = plt.subplots(figsize=(20,20))         # Sample figsize in inches
   sns.heatmap(out, cmap='coolwarm',annot=True, fmt=".1f",annot_kws={'size':8}, ax=ax)
   '''
   fig = plt.figure(figsize=(12,8))
   ax = fig.add_subplot(111)
   ticks = np.arange(0,no_of_features,1)
   ax.set_xticks(ticks)
   ax.set_yticks(ticks)
   ax.set_xticklabels(names, rotation='vertical', size = 8)
   ax.set_yticklabels(names, size = 8)
   #pyplot.show()
   plt.autoscale()
   '''

   plt.savefig("pearson_corr_out.png", bbox_inches = "tight")


   print('++++++++++++++++++++++++++++++++++++++')
   print(out)

   #Ref: https://stackoverflow.com/questions/29432629/plot-correlation-matrix-using-pandas
   #kot1 = corr_matrix.style.background_gradient(cmap='coolwarm')
   #plt.figure(figsize=(12,8))
   #sns.heatmap(kot1, cmap="Greens")
   #plt.savefig("corr_out1.png")

def plot_confusion_matrix(cm, classes,
                          normalize=False,
                          title='Confusion matrix',
                          cmap=plt.cm.Oranges):
    """
    This function prints and plots the confusion matrix.
    Normalization can be applied by setting `normalize=True`.
    Source: http://scikit-learn.org/stable/auto_examples/model_selection/plot_confusion_matrix.html
    """
    plt.clf()
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)

    no_of_features = 18 #CHECK

    # Plot the confusion matrix
    plt.figure(figsize = (10, 10))
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title, size = no_of_features)
    plt.colorbar(aspect=4)
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45, size = 14)
    plt.yticks(tick_marks, classes, size = 14)

    fmt = '.2f' if normalize else 'd'
    thresh = cm.max() / 2.
    
    # Labeling the plot
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, format(cm[i, j], fmt), fontsize = 20,
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")
        
    plt.grid(None)
    plt.tight_layout()
    plt.ylabel('True label', size = 10)
    plt.xlabel('Predicted label', size = 10)
    plt.savefig('cm.png')

def plot_roc(predictions, probs, train_predictions, train_probs, test_labels, train_labels):
    plt.clf()
    """Compare machine learning model to baseline performance.
    Computes statistics and shows ROC curve."""
    
    baseline = {}
    
    baseline['recall'] = recall_score(test_labels, 
                                     [1 for _ in range(len(test_labels))])
    baseline['precision'] = precision_score(test_labels, 
                                      [1 for _ in range(len(test_labels))])
    baseline['roc'] = 0.5
    
    results = {}
    
    results['recall'] = recall_score(test_labels, predictions)
    results['precision'] = precision_score(test_labels, predictions)
    results['roc'] = roc_auc_score(test_labels, probs)
    
    train_results = {}
    train_results['recall'] = recall_score(train_labels, train_predictions)
    train_results['precision'] = precision_score(train_labels, train_predictions)
    train_results['roc'] = roc_auc_score(train_labels, train_probs)
    
    for metric in ['recall', 'precision', 'roc']:
        print(f'{metric.capitalize()} Baseline: {round(baseline[metric], 2)} Test: {round(results[metric], 2)} Train: {round(train_results[metric], 2)}')
    
    # Calculate false positive rates and true positive rates
    base_fpr, base_tpr, _ = roc_curve(test_labels, [1 for _ in range(len(test_labels))])
    model_fpr, model_tpr, _ = roc_curve(test_labels, probs)

    plt.figure(figsize = (16, 12))
    plt.rcParams['font.size'] = 16
    
    # Plot both curves
    plt.plot(base_fpr, base_tpr, 'b', label = 'baseline')
    plt.plot(model_fpr, model_tpr, 'r', label = 'model')
    plt.legend();
    plt.xlabel('False Positive Rate'); 
    plt.ylabel('True Positive Rate'); plt.title('ROC Curves');
    #plt.show();
    plt.savefig('roc_auc_curve.png')

def plot_prec_recall_curve(model, X_test, Y_test):
   plt.clf()
   # predict probabilities
   lr_probs = model.predict_proba(X_test)
   # keep probabilities for the positive outcome only
   lr_probs = lr_probs[:, 1]
   # predict class values
   yhat = model.predict(X_test)
   lr_precision, lr_recall, _ = precision_recall_curve(Y_test, lr_probs)
   lr_f1, lr_auc = f1_score(Y_test, yhat), auc(lr_recall, lr_precision)
   # summarize scores
   print('Logistic: f1=%.3f auc=%.3f' % (lr_f1, lr_auc))
   # plot the precision-recall curves
   no_skill = len(Y_test[Y_test==1]) / len(Y_test)
   plt.figure(figsize = (16, 12))
   plt.plot([0, 1], [no_skill, no_skill], linestyle='--', label='No Skill')
   plt.plot(lr_recall, lr_precision, marker='.', label='Logistic')
   # axis labels
   plt.xlabel('Recall')
   plt.ylabel('Precision')
   # show the legend
   plt.legend()
   # show the plot
   #plt.show()
   plt.savefig('prec_recall.png')

def rf_boruta(df):
  X = df.loc[:, 'registrar':].values
  Y = df.is_phish.values
  #Ref: https://pypi.org/project/Boruta/
  #Ref: https://github.com/scikit-learn-contrib/boruta_py
  # define random forest classifier, with utilising all cores and
  # sampling in proportion to y labels
  rf = RandomForestClassifier(n_jobs=-1, class_weight='balanced', max_depth=5)

  # define Boruta feature selection method
  feat_selector = BorutaPy(rf, n_estimators='auto', verbose=2, random_state=1)

  # find all relevant features - 5 features should be selected
  feat_selector.fit(X, Y)

  print('-----------------------------------')
  print("Number of selected features: " + str(feat_selector.n_features_))

  # check selected features - first 5 features are selected
  print("selector support")
  print(feat_selector.support_)
  #print(len(feat_selector.support_))
  print('-----------------------------------')

  print("selector weak support")
  print(feat_selector.support_weak_)
  print('-----------------------------------')

  # check ranking of features
  print("ranking of features")
  print(feat_selector.ranking_)
  #print(len(feat_selector.ranking_))
  print('-----------------------------------')

  #column headers
  print("Column headers")
  c_hd = list(df.columns.values.tolist()) 
  print(c_hd)
  #print(len(c_hd))
  print('-----------------------------------')

  # call transform() on X to filter it down to selected features
  print("transform")
  X_filtered = feat_selector.transform(X)
  print(X_filtered)
  print('-----------------------------------')

  print("Buruta result summary")
  for i in range(len(c_hd)):
    if i == 0: continue
    print(c_hd[i] + " -- " + str(feat_selector.support_[i-1]) + ' -- ' + str(feat_selector.ranking_[i-1]))

  #print("Filtered column headers")
  #print(X_filtered.columns.values.tolist())

'''
#Ref: https://towardsdatascience.com/the-3-ways-to-compute-feature-importance-in-the-random-forest-96c86b49e6d4
def rf_feature_importances(classifier, df, model):
   sorted_idx = classifier.feature_importances_.argsort()
   #plt.barh(df.feature_names[sorted_idx], classifier.feature_importances_[sorted_idx])
   print('----------------------')
   print(sorted_idx)
   print('----------------------')
   print(df.columns)
   plt.clf()
   plt.barh(df.columns[sorted_idx], classifier.feature_importances_[sorted_idx])
   
   #plt.barh(df.columns, classifier.feature_importances_)

   plt.xlabel("Random Forest Feature Importance")
   plt.savefig('rf_feature_imp')
   print("RRRRRRRRRRRRRRRRRRRRRRRRRRR")
   print( classifier.feature_importances_)
   print(model.feature_names)
'''

def create_models(df):
   rf_classifier = RandomForestClassifier(n_estimators= 20, random_state= 99)
   rf_create_model(df, rf_classifier, "rf")

   #Ref: https://datascience.stackexchange.com/questions/48693/perform-k-means-clustering-over-multiple-columns
   #km_classifier = KMeans(n_clusters=2, random_state = 0) #, precompute_distances="auto")
   #km_model = km_create_model(df, km_classifier, "km")

def km_create_model(df, classifier, cl_label):
   categorical_var = ["registrar","ns","ns_sld","ns_asn","registrant_org","registrant_country"]
   df = pd.get_dummies(df, columns=categorical_var)
   
   X = df.drop('is_phish', axis=1)
   Y = df['is_phish']

   X_train, X_test, Y_train, Y_test = train_test_split(X,Y,test_size=0.2, random_state=0)

   training_accuracy = cross_val_score(classifier, X_train, Y_train, cv=5, scoring='accuracy').mean()
   print(cl_label + " - training score: " + str(training_accuracy))

   model = classifier.fit(X_train,Y_train)

   save_model(model, cl_label)
   pickle_model = load_model(cl_label)

   Y_pred = pickle_model.predict(X_test)
   plt.clf()

   #Run PCA to reduce dimensions
   pca_num_components =  2
   reduced_data = PCA(n_components=pca_num_components).fit_transform(X)
   results = pd.DataFrame(reduced_data,columns=['pca1','pca2'])

   
   '''
   sns.scatterplot(x="pca1", y="pca2", hue=Y_pred, data=results)
   plt.title('K-means Clustering with 2 dimensions')
   plt.savefig('pca')
   ''' 

   cm = confusion_matrix(Y_test, Y_pred)
   plot_confusion_matrix(cm, classes = [0,1],
                      title = 'Confusion Matrix')

   testing_accuracy = accuracy_score(Y_test, Y_pred)
   print(cl_label + " Testing accuracy: " + str(testing_accuracy))



def rf_create_model(df, classifier, cl_label):
  print("=======================================")
  print("Processing " + cl_label + " model....")
  #print(df.describe().T)


  utc_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
  #classifier = RandomForestClassifier(n_estimators= 100, random_state= 0)

  #deal with categorical variables
  #drop w_ns_asn
  categorical_var = ["w_registrar","w_ns","w_ns_sld","w_ns_geo","w_ns_asn","w_registrant_org","w_registrant_country","d_domain_tld","c_cert_issuer_name","c_cert_issuer_country"]
  #categorical_var = ["ns"]
  numerical_var = ["w_domain_life_span","d_min_lev_distance","d_no_of_sub_domains","c_is_cert_issued_from_free_ca","d_has_suspicious_tld_in_domain","d_has_tlds_in_sub_domain","d_number_of_hyphens_in_domain","d_number_of_hyphens_in_sub_domain","d_shannon_entropy","d_domain_length","d_number_of_digits","d_is_domain_resolves","c_cert_lifespan","d_no_of_consecutive_characters","d_has_special_chars","s_number_of_links","s_int_ext_links_ratio","s_number_exteral_css","s_empty_actions","s_iframes_with_invisible_border","s_unsafe_anchors","s_empty_title","s_is_domain_withon_copyright_sym"]
  #df = pd.get_dummies(df, columns=categorical_var)
  
  #standard_scaler = StandardScaler()
  #df = pd.DataFrame(standard_scaler.fit_transform(df), columns=numerical_var, 

  #X = df.loc[:, 'registrar':]
  X = df.drop('is_phish', axis=1)
  Y = df['is_phish']

  print_column_names(df)

  #print("11111111111111111")
  X_train, X_test, Y_train, Y_test = train_test_split(X,Y,test_size=0.2, random_state=99)
  #print("22222222222222222222")

  column_trans = make_column_transformer(
        (StandardScaler(), numerical_var),
        (OneHotEncoder(handle_unknown='ignore'), categorical_var),
        #remainder=StandardScaler())
        remainder='passthrough')
        #remainder='passthrough')

  pipe = make_pipeline(column_trans, classifier)
  print("############### Applying " + cl_label + " - on TRAIN data")

  training_accuracy = cross_val_score(pipe, X_train, Y_train, cv=5, scoring='accuracy').mean()
  print(cl_label + " - training score: " + str(training_accuracy))

  #pipe instead of mode - train ~ fit
  model = pipe.fit(X_train,Y_train)

  #Determine feature importances
  #rf_feature_importances(classifier, df, model)

  #predictors = X_train.columns
  #coef = pd.Series(classifier.coef_.predictors).sort_values()
  #print(coef)
  
  if cl_label == "rf":
     plt.clf()
     print('--------------------------------------')
     #ROC Curve
     ns_probs = [0 for _ in range(len(Y_test))]
     # predict probabilities
     lr_probs = model.predict_proba(X_test)
     # keep probabilities for the positive outcome only
     lr_probs = lr_probs[:, 1]
     # calculate scores
     ns_auc = roc_auc_score(Y_test, ns_probs)
     lr_auc = roc_auc_score(Y_test, lr_probs)
     # summarize scores
     print('No Skill: ROC AUC=%.3f' % (ns_auc))
     print('Logistic: ROC AUC=%.3f' % (lr_auc))
     # calculate roc curves
     ns_fpr, ns_tpr, _ = roc_curve(Y_test, ns_probs)
     lr_fpr, lr_tpr, _ = roc_curve(Y_test, lr_probs)
     # plot the roc curve for the model
     plt.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
     plt.plot(lr_fpr, lr_tpr, marker='.', label='Logistic')
     # axis labels
     plt.xlabel('False Positive Rate')
     plt.ylabel('True Positive Rate')
     # show the legend
     plt.legend()
     # show the plot
     #plt.show()
     plt.savefig('roc_' + cl_label)
  

  save_model(model, cl_label)
  pickle_model = load_model(cl_label)

  ###Y_pred = pipe.predict(X_test)
  Y_pred = pickle_model.predict(X_test)

  y_label = np.unique(Y_pred)
  ##print(u_label)

  '''
  if cl_label == "km":
     plt.clf()
     centers = classifier.cluster_centers_
     plt.scatter(centers[:, 0], centers[:, 1], c=y_label, s=50, cmap='viridis');
     #print(len(Y_pred[:, False]))
     #print(Y_pred[:, False])
     #print(len(Y_pred[:, True]))
     #print(Y_pred[:, True])
     #plt.scatter(Y_pred[:, False], Y_pred[:, True], c=y_label, s=200, alpha=0.5);
     #for i in u_label:
     #    print(i)
     #    plt.scatter(df[Y_pred == i , False] , df[Y_pred == i , True] , Y_pred = i)
     plt.savefig('km_scatter')
     #centers = pickle_model.cluster_centers_
     #plt.scatter(centers[:, 0], centers[:, 1], c='black', s=200, alpha=0.5);
  '''

  print('-----------------------')
  print("###### Applying " + cl_label + " - on TEST data")
  ##################print(Y_pred)
  #Y_pred_probea = pickle_model.predict_probea(X_test)
  #print(Y_pred_probea)
  print('-------------------------')

  cm = confusion_matrix(Y_test, Y_pred)
  #print(cm)
  plot_confusion_matrix(cm, classes = [0,1],
                      title = 'Confusion Matrix')

  
  #plt.savefig('cm.png')
  # Training predictions (to demonstrate overfitting)
  if cl_label == "rf":
     train_predictions = model.predict(X_train)
     train_probs = model.predict_proba(X_train)[:, 1]

     # Testing predictions (to determine performance)
     predictions = model.predict(X_test)
     probs = model.predict_proba(X_test)[:, 1]

     #Plot curves
     plot_roc(predictions, probs, train_predictions, train_probs, Y_test, Y_train)
     plot_prec_recall_curve(model, X_test, Y_test)
  
  
  print('--------------------------------------------')
  print(classification_report(Y_test, Y_pred))
  testing_accuracy = accuracy_score(Y_test, Y_pred)
  print(cl_label + " Testing accuracy: " + str(testing_accuracy))
  print('--------------------------------------------')

  conn = None
  cursor = None

  try:
     if date_yesterday:
        date_yesterday_1 = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time_yesterday))
        utc_date = datetime.strptime(date_yesterday_1, '%Y-%m-%d %H:%M:%S')
     conn = connect_result()
     cursor = conn.cursor()
     vals = (utc_date, "is_phish", cl_label, float(training_accuracy), float(testing_accuracy))
     query = 'INSERT IGNORE INTO `prediction_stats` (ts,predict_type,alg,training_accuracy,testing_accuracy) VALUES (%s,%s,%s,%s,%s);'
     #cursor.execute(query, vals) #REMOVE
     #conn.commit()
  except Exception as e:
     print(str(e))
     traceback.print_exc(file=sys.stdout)
  finally:
     if cursor is not None: cursor.close()
     if conn is not None: conn.close()
  return model



#### MAIN ####
def main(argv):
   global date_yesterday
   init()
   create_db()

   try:
      opts, args = getopt.getopt(argv,"h:",[])
   except getopt.GetoptError:
      print(sys.argv[0])
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print(sys.argv[0])
         sys.exit()

   save_data_as_csv()

   
   df = load_data(data_path)
   
   df = clean_data(df, 1)

   print(df)
   data_types(df)
   
   
   do_corr(df, "is_phish")
   
   ###nan_fields(df)
   ##value_counts_of_field(df, 's_forms_with_empty_actions')
   ###uniq_vals(df, 'w_registrar')
   
   #res = [col for col in df if (df[col] == -1).any()]
   #print(res)
 
    
   create_models(df)
   ####rf_boruta(df)
    


#### MAIN ####
if __name__ == '__main__':
    main(sys.argv[1:])
