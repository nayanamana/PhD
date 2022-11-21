#!/usr/bin/python

import re
import os
import inspect
import subprocess
import argparse
import datetime
from time import time, strftime, localtime

#site_file = '/home/naya/phd/ph_exp/data/alexa-1m.csv'
site_file = '/home/naya/phd/ph_exp/data/tranco-1m.csv'
site_out = '/home/naya/phd/ph_exp/results/ph_sites'

fh = open(site_file, 'r')
f_out = open(site_out, "a+")

proc_data = []


### MAIN ###
if __name__ == "__main__":
   parser = argparse.ArgumentParser(description="Extract phishing sites")
   parser.add_argument("-i", metavar='I', type=str,
                        help="Input file")
   parser.add_argument("-o", metavar='O', type=str,
                        help="Output file")
   parser.add_argument("-s", metavar='S', type=int,
                        help="Start from")
   args = parser.parse_args()

   in_file = args.i
   out_file = args.o
   s_from = args.s

   if not (in_file and out_file and s_from):
      print "Incorect arguements provided. Please run with correct args"
      cur_scr = inspect.getfile(inspect.currentframe())
      print "Examples:"
      print cur_scr + ' -i "' + site_file + '" -o "' +  site_out + '" -s 1'
      print ""
      exit(0)

   print "Process started at: " + strftime("%Y-%m-%d %H:%M:%S", localtime())

   for site_str in fh:
      site_str = site_str.strip()
      site_arr = site_str.split(' ')

      site_file = in_file
      site_out = out_file 
   
      match = re.search("(\d+)\s+(\S+)", site_str)
      if (match):
        site_no = match.group(1)
        if (int(s_from) > int(site_no)):
           continue
        dom =  match.group(2)     
        try:
           cmd_dnstwist = ['/home/naya/phd/tools/dnstwist/dnstwist.py','-r','--ssdeep','-f','csv','--threads','40',dom]
           cmd_output = subprocess.check_output(cmd_dnstwist)
           cmd_output = cmd_output.strip()
           #print cmd_output
           cmd_output_arr = cmd_output.split('\n')
        except Exception as e:
           print str(e)
           continue

        for e in cmd_output_arr:
           try:
              e_arr = e.split(',')
              #print "LENGTH: " + str(len(e_arr))
              fuzzer = e_arr[0] if e_arr[0] else ""
              domain_name =  e_arr[1] if e_arr[1] else ""
              dns_a =  e_arr[2] if  e_arr[2] else ""
              dns_aaaa = e_arr[3] if e_arr[3] else ""
              dns_mx = e_arr[4] if  e_arr[4] else ""
              dns_ns =  e_arr[5] if e_arr[5] else ""
              geoip_country = e_arr[6] if e_arr[6] else ""
              whois_created = e_arr[7] if e_arr[7] else ""
              whois_updated = e_arr[8] if e_arr[8] else ""
              ssdeep_score = e_arr[9] if e_arr[9] else ""
              proc_data.append({'fuzzer': fuzzer,'domain-name': domain_name, 'site_rank': site_no, 'dns-a': dns_a,'dns-aaaa': dns_aaaa,'dns-mx': dns_mx,'dns-ns': dns_ns,'geoip-country': geoip_country,'whois-created': whois_created,'whois-updated': whois_updated,'ssdeep-score': ssdeep_score})
              if not ("fuzzer" in fuzzer):
                if dns_a: #if IP address exists
                   f_out.write(fuzzer + '	' + domain_name + '	' + site_no + '	' + dns_a + '	' + ssdeep_score + "\n") 
           except Exception as e:
              print str(e)
              continue
      #break

   f_out.close()
   print "Process ended at: " + strftime("%Y-%m-%d %H:%M:%S", localtime())

