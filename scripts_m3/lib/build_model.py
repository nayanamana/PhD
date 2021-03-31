#!/usr/local/bin/python3.8

# Author:   Samuel Marchal samuel.marchal@aalto.fi
# Copyright 2015 Secure Systems Group, Aalto University, https://se-sy.org/
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys,statistics

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn import metrics
import pandas as pd
import numpy as np
import pickle
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

def predict_urls(df, model_file):
  url_list = []
  f = open(model_file,'rb')
  clf = pickle.load(f)
  f.close()
  #cnt = 0
  threshold = 0.7

  counter = 0
  counter_phish = 0
  print("#### Predicted phishing URL ####")
  for index, row in df.iterrows():
     counter += 1
     url = row['start_url']
     row_copy = row
     row_copy.drop("start_url", inplace=True)
     row_copy.drop("label", inplace=True)
     row_copy = row_copy.values.reshape(1,-1)
     Y_pred = clf.predict(row_copy)
     Y_prob_score = clf.predict_proba(row_copy)
     #print("PRED: " + str(Y_pred[0]))
     #print("PRED SCORE: "+ str(Y_prob_score[:,1][0]))
     if Y_pred[0] == 1 and Y_prob_score[:,1][0] > threshold:
        #cnt += 1
        counter_phish += 1
        prob = str(round(Y_prob_score[:,1][0],3))

        #print(prob + ',' + url)
        print(url)
        #print(str(Y_prob_score[:,1][0]))
        url_list.append(url)
  #print("CNT: " + str(cnt))

  print('----------------------------------')
  print("Phishing URLs: " + str(counter_phish))
  print("Benign URLs:" + str(counter-counter_phish))
  return url_list


def build_gb(train,features,model_file):

    trai, _  = pd.factorize(train['label'])
    clf = GradientBoostingClassifier(n_estimators=500,max_depth=3)#(n_estimators=300,max_depth=3)
    clf.fit(train[features], trai)
    f = open(model_file,'wb')
    pickle.dump(clf,f)
    f.close()

def predict_gb(test,features,model_file):
    tes, _ = pd.factorize(test['label'])
    f = open(model_file,'rb')
    clf = pickle.load(f)
    f.close()

    mode = 101 # 1: use threshold / 10: print features importance / 100: print missclassified instances

    if mode % 10 == 1:
        threshold = .7
    else:
        threshold = .5

    #--------------------------
    pr_new = clf.predict(test[features])
    #print(pr_new)
    #print("wwww")
    #print(test)


    #--------------------------

    preds = clf.predict_proba(test[features])
    prediction = np.array([])
    for x in np.nditer(preds[:,1]):
        if x < threshold:
            prediction = np.append(prediction,0)
        else:
            prediction = np.append(prediction,1)


    i = 0
    hr_feat = set()

    for x in np.nditer(clf.feature_importances_):
        if x >= .015 or x <-.02:
            hr_feat.add(i)
            if mode % 100 >=10:
                print(str(i) + " " + str(x))
        i+= 1
  
  
    #metric computation
    false = test[test['label'] != prediction]

    negative = len(test[test['label'] == 0].index)#
    positive = len(test[test['label'] == 1].index)
    fp = len(false[false['label'] == 0].index)
    fn = len(false[false['label'] == 1].index)
    tp = positive - fn
    tn = negative - fp


    '''
    fprate = float(fp) / float(negative)
    precision = float(tp) / float(tp+fp)
    recall = float(tp) / float(tp+fn)
    accuracy = float(tp+tn) / float(tp+tn+fp+fn)
    f1 = (2*precision*recall) / (precision + recall)
    '''
    fprate = 0
    recall = 0
    precision = 0
    accuracy = 0
    f1 = 0

    if negative: fprate = float(fp) / float(negative)
    if (tp+fp): precision = float(tp) / float(tp+fp)
    if (tp+fn): recall = float(tp) / float(tp+fn)
    if (tp+tn+fp+fn): accuracy = float(tp+tn) / float(tp+tn+fp+fn)
    if (precision + recall): f1 = (2*precision*recall) / (precision + recall)

    
    print(negative,fp,fn,tp,tn,fprate,precision,recall,accuracy,f1)
    print(metrics.precision_recall_fscore_support(test['label'], prediction, average='binary'))


    print("\nGradient Boosting classification results:")
    print(pd.crosstab(test['label'], prediction, rownames=['actual'], colnames=['preds']))
    print("\n")
    print(classification_report(test['label'], prediction))
    

    test["score"] = preds[:,1]
    if mode % 1000 >=100:
        fw = open("intel-res-kiran.csv",'w')
        one = np.array([1]*test.shape[0])

        for index, row in test[test['label'] == one].iterrows():
            fw.write(str(row["start_url"])+","+str(row["score"])+"\n")#+","+str(row["land_url"])+","+str(row["score"])+"\n")#,"land_url","score"]]))
        fw.close()

        
        #print(test[test['label'] != prediction][["start_url"]]),"label","score"]])
        #fw.write(str(test[test['label'] == one][["start_url","land_url","score"]]))

    return hr_feat


if __name__=="__main__":
    pass

    '''
    if len(sys.argv) < 5:
        print("build_model.py mode(0:learn/1:predict) legit phish exp_name")
    else:
        #loading

        mode = sys.argv[1]
        leg = pd.read_pickle(sys.argv[2])
        phish = pd.read_pickle(sys.argv[3])
        exp = sys.argv[4]

        pd.set_option('display.max_rows', 10000)
        pd.set_option('display.max_columns', 10000)
        np.set_printoptions(threshold=10000)
        
        
        feat_vect = pd.concat([leg,phish],ignore_index=True)
        feat_vect = feat_vect.fillna(0)

        features = feat_vect.columns
        features = features.drop(["start_url","label"])


        features_norm = features

        if int(mode) == 0:
            build_gb(feat_vect,features,exp)

        else:

            predict_gb(feat_vect,features,exp)
    '''

