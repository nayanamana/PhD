#!/usr/bin/python

import os
import sys
import re
import glob
import json
import time
import shutil

src_dir = '/mnt/extra2/projects/0919_cl/cloaking/results'
dest_dir = '/mnt/extra2/projects/0919_cl/cloaking/results_cl'

cl_list_file = '/mnt/extra2/projects/0919_cl/cloaking/data/new_cloaked_sites'

with open(cl_list_file, 'r') as f:
   for line in f:
     line = line.strip()
     line = line.replace('www.','')
     re_line = re.search('://(.+)\.', line)
     if (re_line):
        site_dom = re_line.group(1)
        #print(site_dom)
        for file in glob.glob(src_dir + '/*' + site_dom + '*screen*chrome_1.png'):
           #print(file)
           shutil.copy(file, dest_dir)
        for file in glob.glob(src_dir + '/*' + site_dom + '*source*chrome_1.txt'):
           shutil.copy(file, dest_dir)

