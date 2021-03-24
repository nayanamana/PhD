#!/usr/local/bin/python3.8

import warnings
import sys, os, json
warnings.filterwarnings('ignore')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import ofh_save_page
import build_feat_vect

def save_pages(dir_name):
   url = 'https://www.paypal-me-alessandra-martini.com'
   is_phish = 1
   ofh_save_page.fetch_and_save_data(url, dir_name, is_phish)

def extract_features(dirname):
   build_feat_vect.build_feature_vector(dirname)

def main():
   ##out_page_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_out_b'
   ##url = 'https://mydesk.morganstanley.com'
   #url = "https://cbc.ca"

   out_page_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_out_m'
   #url = 'https://www.paypal-me-alessandra-martini.com'
   #ofh_save_page.fetch_and_save_data(url, out_page_dir)

   save_pages(out_page_dir)

   #extract_features(out_page_dir)


### MAIN ###
if __name__ == "__main__":
    main()

