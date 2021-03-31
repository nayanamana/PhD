#!/usr/local/bin/python3.8

import os,sys,json
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/1-Squatting-Domain-Identification')

import utils
import squatting_type

import squatting_scan

url_file = '/mnt/extra1/projects/phishing/scripts_m3/url_lists/list_250321'

url_list = []
with open(url_file) as f:
    url_list = f.read().splitlines()

for d in url_list:
   #print(d)
   type_obj = squatting_scan.get_type(d)
   #print(d + ',' + str(type_obj[0]))
   ##if len(type_obj) > 0:
   ##   print(type_obj)
   ##########print(d + ',' + str(type_obj))

#print(url_list)

