#!/usr/bin/python

import os
import datetime
import json
import time
import sqlite3
#from subprocess import call
import subprocess
import traceback
import sys
import glob
import os
import re

#Change this appropiately
max_no_of_sites = 10000
#max_no_of_sites = 3


#base_dir = '/home/naya/'
###base_dir = os.path.expanduser('~')
base_dir = '/mnt/extra2/projects/0919_cl'
cloak_log = base_dir + '/cloaking/logs/site_debug.log'
script = base_dir +  '/cloaking/scripts/cloak_gc.js'
nodejs_path = '/usr/bin/nodejs'

def getpid(process_name):
   for path in glob.glob('/proc/*/comm'):
        if open(path).read().rstrip() == process_name:
            return path.split('/')[2]

### MAIN ###
#If log file does not exist
if not os.path.exists(cloak_log):
   #cmd_arr = [nodejs_path,script,'>',cloak_log]
   cmd_str = "/usr/bin/touch " + cloak_log
   subprocess.call(cmd_str, shell=True)
   cmd_str = nodejs_path + " " + script + " " + str(1) + " " + str(max_no_of_sites) + " > " + cloak_log + " &"
   print("Running command.. : " + cmd_str)
   subprocess.call(cmd_str, shell=True)

#sleep 10 seconds
time.sleep(10)

next_site_index = 1

while True:
   file_mod_time = os.stat(cloak_log).st_mtime
   # Time in seconds since epoch for time, in which logfile can be unmodified.
   should_time = time.time() - (30 * 60)
   # Time in minutes since last modification of file
   last_time = (time.time() - file_mod_time) / 60

   with open(cloak_log, 'r') as f:
      lines = f.read().splitlines()
      last_line = lines[-1]
      matched = re.match('^(.+?)\s+(\d+)\s+',last_line)
      if (matched):
         next_site_index = int(matched.group(2)) + 1

   if (last_time > 10): #more than 10 mins, take action
      pid = getpid('nodejs');
      print("cloak_gc.js process may have stopped " + str(last_time))
      now = datetime.datetime.now()
      if pid:
         print(str(now) + " -- Running '/bin/kill -TERM " + pid + "'")
         cmd_arr = ["/bin/kill", '-TERM', pid]
         subprocess.call(cmd_arr)
      else:
         #cmd_arr = [nodejs_path,script,str(next_site_index),'>>',cloak_log] 
         cmd_str = nodejs_path + " " + script + " " + str(next_site_index) + " " + str(max_no_of_sites) +  " >> " + cloak_log + " &"
         print("Restarting command... : " + cmd_str)
         subprocess.call(cmd_str, shell=True)
   time.sleep(60)

