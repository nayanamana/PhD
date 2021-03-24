#!/usr/local/bin/python3.8

import sys,os,json,re
import subprocess

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
sys.path.append('/var/tmp/squatphish/1-Squatting-Domain-Identification')
import utils
import squatting_scan

dom_list = '/mnt/extra1/projects/phishing/scripts_m2/whoisds_domains/whoisdom_220321'

f_w = open("/var/tmp/whoisds_typo_sq", "w+")

if __name__ == "__main__":
   #s = squatting_scan.get_type(test)
   with open(dom_list, 'r') as r_f:
     line = r_f.readline()
     while line != '':
        #line = 'gooogle.com'
        try:
           line = line.strip()
           out = subprocess.check_output('/var/tmp/squatphish/1-Squatting-Domain-Identification/squatting_scan.py ' + line, shell=True)
           out = out.strip()
           out = out.decode('utf-8')

           #print(out)
           re_m = re.search("\[\['(.+?)', '(.+)'\]\]", out)
           if re_m:
              d = re_m.group(1)
              t = re_m.group(2)
              line_str = line + '	' + d + '	' + t
              print(line_str)
              f_w.write(line_str + '\n')
        except Exception as e:
           pass

f_w.close()
