#!/usr/local/bin/python3.8

import sys, os, json
import subprocess
import traceback
import glob

#Ref - https://pypi.org/project/pyasn/

def download_ipasn_dat_file():
   cmd = 'cd /mnt/extra1/projects/phishing/data/;/usr/local/bin/pyasn_util_download.py --latest'
   print("Running command => " + cmd)
   output = subprocess.getoutput(cmd)
   print(output)
   print('--------------------------------------')

def get_latest_ipasn_file():
   pattern = '/mnt/extra1/projects/phishing/data/rib.*.bz2'
   list_of_files = glob.glob(pattern) 
   latest_file = max(list_of_files, key=os.path.getctime)
   return latest_file

def convert_file(file_path):
   if not file_path: return
   cmd = '/usr/local/bin/pyasn_util_convert.py --single ' + str(file_path) + ' /mnt/extra1/projects/phishing/data/ipasn.dat_bak;/bin/mv /mnt/extra1/projects/phishing/data/ipasn.dat_bak /mnt/extra1/projects/phishing/data/ipasn.dat;/bin/rm ' + str(file_path)
   print("Converting file: " + str(file_path) + " to " + "/mnt/extra1/projects/phishing/data/ipasn.dat")
   output = subprocess.getoutput(cmd)
   print(output)
   print('--------------------------------------')

def main():
   download_ipasn_dat_file()
   ipasn_dat_file = get_latest_ipasn_file()
   convert_file(ipasn_dat_file)

### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main()


