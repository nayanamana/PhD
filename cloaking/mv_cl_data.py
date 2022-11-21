#!/usr/bin/python

import os
import sys
import json
import re
import glob
from shutil import copyfile

file_cl_data = '/mnt/extra2/projects/0919_cl/cloaking/data/new_cloaked_sites'
file_non_cl_data = '/mnt/extra2/projects/0919_cl/cloaking/data/new_not_cloaked_sites'

dir_results = '/mnt/extra2/projects/0919_cl/cloaking/results/'
dir_dest_cl = '/mnt/extra2/projects/0919_cl/cloaking/sep_data/cl'
dir_dest_non_cl = '/mnt/extra2/projects/0919_cl/cloaking/sep_data/non_cl'

src_files = glob.glob(dir_results + '/*')

for i_file in src_files:
   #print(i_file)
   f_cl = open(file_cl_data, "r")
   for file in f_cl:
     file = file.strip()
     m_f_dom = re.search('://(.+)', file)
     if m_f_dom:
       f_dom = m_f_dom.group(1) 
       #print(f_dom)
       if f_dom in i_file:
          #print(f_dom + ' -- ' + i_file)
          m_fname = re.search('.+/(.+)$', i_file)
          if m_fname:
             f_name = m_fname.group(1)
             copyfile(i_file, dir_dest_cl + '/' + f_name)

   f_non_cl = open(file_non_cl_data, "r")
   for file in f_non_cl:
     file = file.strip()
     m_f_dom = re.search('://(.+)', file)
     if m_f_dom:
       f_dom = m_f_dom.group(1)
       #print(f_dom)
       if f_dom in i_file:
          #print(f_dom + ' -- ' + i_file)
          m_fname = re.search('.+/(.+)$', i_file)
          if m_fname:
             f_name = m_fname.group(1)
             copyfile(i_file, dir_dest_non_cl + '/' + f_name)

