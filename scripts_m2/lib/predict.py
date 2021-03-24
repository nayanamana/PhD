#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import numpy as np
from sklearn import decomposition
#from sklearn.externals import joblib
import joblib

import model
import feature_extract

import sys
import os

# concurrent preidction
# from concurrent.futures import TimeoutError

model_path = '/mnt/extra1/projects/phishing/scripts_m1/saved_models/forest_pca.pkl'
model_path_dt = '/mnt/extra1/projects/phishing/scripts_m1/saved_models/forest_pca_dt.pkl'

x_path = '/mnt/extra1/projects/phishing/scripts_m1/data/X.txt'
y_path = '/mnt/extra1/projects/phishing/scripts_m1/data/Y.txt'

x_path_dt = '/mnt/extra1/projects/phishing/scripts_m1/data/X_dt.txt'
y_path_dt = '/mnt/extra1/projects/phishing/scripts_m1/data/Y_dt.txt'

no_of_components = 19

def parse_options():
    parser = argparse.ArgumentParser(description="running analysis...", prefix_chars='-+/')
    parser.add_argument('-t', '--html', type=str,
                        help='A html source data to extract features')
    parser.add_argument('-i', '--img', type=str,
                        help='A image data to extract features')
    args = parser.parse_args()
    return args

def load_model():
    #print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X)

    #print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X)
        X = pca2.transform(X)
        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)
    return {'model': forest, 'pca': pca}

def load_model_dt():
    #print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X)

    #print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path_dt)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X)
        X = pca2.transform(X)
        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)
    return {'model': forest, 'pca': pca}

def predict_min(domain,content_html, content_img, clf, pca):
    if clf == None or pca == None:
      print("Error: Model/PCA not initialized")
      return
    #print(domain)
    #print(content_html)
    v = feature_extract.feature_vector_extraction(domain,content_html, content_img)
    if not v:
        print("Fail to extract feature vectors.")
        return

    new_v = pca.transform(np.asarray(v).reshape(1, -1))
    p_prob = clf.predict_proba(new_v)
    p = clf.predict(new_v)
    #print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    return {'decission': int(p.tolist()[0]), 'prob': p_prob.tolist()[0], 'heuristics': str(v)}

def predict(domain,content_html, content_img):
    print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X)

    print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X)
        X = pca2.transform(X)
        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)

    v = feature_extract.feature_vector_extraction(domain,content_html, content_img)
    if not v:
        print("Fail to extract feature vectors.")
        return

    new_v = pca.transform(np.asarray(v).reshape(1, -1))
    p_prob = forest.predict_proba(new_v)
    p = forest.predict(new_v)
    print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    return p 

def predict_dt(domain,content_html, content_img):
    x_path = '/mnt/extra1/projects/phishing/scripts_m1/data/X.txt'
    y_path = '/mnt/extra1/projects/phishing/scripts_m1/data/Y.txt'

    print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X)

    print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path_dt)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X)
        X = pca2.transform(X)
        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)

    v = feature_extract.feature_vector_extraction(domain,content_html, content_img)
    if not v:
        print("Fail to extract feature vectors.")
        return

    print("##### HEURISTICs: ")
    print(v)

    new_v = pca.transform(np.asarray(v).reshape(1, -1))
    p_prob = forest.predict_proba(new_v)
    p = forest.predict(new_v)
    print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    #return p
    return {'decission': int(p.tolist()[0]), 'prob': p_prob.tolist()[0]}



'''
def main():
    args = parse_options()

    img = os.path.abspath(args.img)
    html = os.path.abspath(args.html)

    print ("Run the prediction...")
    predict(img, html)

    return


if __name__ == "__main__":

    sys.exit(main())
'''
