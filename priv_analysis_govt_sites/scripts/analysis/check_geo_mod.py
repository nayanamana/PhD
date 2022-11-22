#!/usr/local/bin/python3.8

import warnings
warnings.filterwarnings('ignore')

import pandas as pd
#Ref: https://codereview.stackexchange.com/questions/217065/calculate-levenshtein-distance-between-two-strings-in-python
#from Levenshtein import distance as levenshtein_distance
import tldextract
import json
import yaml
import re
import math
import traceback
import sys, os
from datetime import datetime
import time
from datetime import timezone
import re
import subprocess
import pydig
import ipwhois
#import pyasn
from geoip import geolite2
from collections import Counter
from string import printable

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import traceback
import requests
from bs4 import BeautifulSoup

import math
from collections import Counter
import socket

#See https://pypi.org/project/pyasn/ how to generate these files
#asndb = pyasn.pyasn('/mnt/extra1/projects/phishing/data/ipasn.dat')

def get_ip(dom):
  try:
     obj = socket.gethostbyname(dom)
     return str(obj)
  except Exception as e:
     pass
     return ""

def get_country(ip):
   try:
      ip = str.encode(ip)
      geo_obj = geolite2.lookup(ip)
      c = geo_obj.country
      return c
   except Exception as e:
       return ''


if len(sys.argv) < 3:
    sys.exit(1)
inp_file = sys.argv[1]
out_file = sys.argv[2]

out_list = []
with open(inp_file, 'r') as f_r:
    for line in f_r:
        line = line.strip()
        if line == "": continue
        line_arr = line.split('|')
        dom = line_arr[1]
        ip = get_ip(dom)
        geo = get_country(ip)
        ln = line + '|' + ip + '|' + geo
        out_list.append(ln)
        print(ln)

with open(out_file, 'a+') as the_file:
    for l in out_list:
       the_file.write(str(l) + "\n")
