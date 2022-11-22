#!/home/naya/miniconda3/bin/python3

import json, re, sys, os
import sqlite3
from sqlite3 import Error

import pandas as pd
import csv
import tldextract
import glob
import json,traceback

import requests
import datetime
import calendar
import tldextract
import subprocess

from os.path import exists

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode, b64encode

import ecdsa

#Ref https://pypi.org/project/ecdsa/
from ecdsa import ECDH, NIST256p, NIST192p


def process():
   if len(sys.argv) < 2:
      print("Either in_file OR out_file not specified")
      print("Example:")
      #print("/mnt/extra1/projects/religious_sites/scripts/scan_with_wapiti.py /mnt/extra1/projects/religious_sites/results/filter_fp_vuln_site_domains.csv /mnt/extra1/projects/religious_sites/sec_issues/s/")
      print("/mnt/extra1/projects/religious_sites/scripts/scan_with_wapiti.py /mnt/extra1/projects/religious_sites/results/filtered_religious_sites_site_visits_out.csv /mnt/extra1/projects/religious_sites/sec_issues/a/")
      sys.exit(0)

   in_file = sys.argv[1]
   out_dir = sys.argv[2]

   if not os.path.exists(in_file):
       print("No valid input file: " + in_file)
       sys.exit(0)

   if not os.path.isdir(out_dir):
       print("No valid output directory: " + out_dir)
       sys.exit(0)

   counter = 1
   for domain in open(in_file):
      domain = domain.strip()
      print(str(counter) + " # Process domain: " + domain)
      counter += 1

      out_file_n = out_dir + "/seciss_" + domain + ".json"

      try:
         #cmd = '/usr/local/bin/wapiti -u "https://"' + domain + ' --max-scan-time 15 --max-attack-time 15  -f json -t 15 -d 5 -o ' + out_file_n  + ' --verify-ssl 0'
         #os.system(cmd)
         cmd_list = ['/usr/local/bin/wapiti', '-u', "https://" + domain, '--max-scan-time', '15', '--max-attack-time', '15', '-f', 'json', '-t', '15', '-d', '10', '-o', out_file_n]
         #cmd_list = ['/usr/local/bin/wapiti', '-u', "https://" + domain, '--max-scan-time', '15', '--max-attack-time', '15', '-f', 'json', '-t', '15', '-o', out_file_n]
         #Ref: https://stackoverflow.com/questions/57704601/python-os-system-set-max-time-execution
         subprocess.run(cmd_list, timeout=60)
      except Exception as e:
         print(str(e))
         pass

      #break #REMOVE


def main():
   process()


if __name__ == '__main__':
    main()

