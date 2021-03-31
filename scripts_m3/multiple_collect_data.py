#!/usr/local/bin/python3.8

import os,sys,json
from subprocess import Popen, PIPE
from datetime import datetime
import time

#from fsplit.filesplit import Filesplit

def print_usage():
    print("USAGE: " + sys.argv[0] + " /mnt/extra1/projects/phishing/scripts_m3/url_lists/list_250321")

#Ref: https://code.activestate.com/recipes/578045-split-up-text-file-by-line-count/
def split_file(filepath, lines_per_file):
    """splits file at `filepath` into sub-files of length `lines_per_file`
    """
    lpf = lines_per_file
    path, filename = os.path.split(filepath)
    with open(filepath, 'r') as r:
        #name, ext = os.path.splitext(filename)
        name = filename
        try:
            counter = 1
            w = open(os.path.join(path, '{}_{}'.format(name, counter)), 'w')
            for i, line in enumerate(r):
                if not i % lpf:
                    #possible enhancement: don't check modulo lpf on each pass
                    #keep a counter variable, and reset on each checkpoint lpf.
                    w.close()
                    filename = os.path.join(path,
                                            '{}_{}'.format(name, counter))
                    counter += 1
                    w = open(filename, 'w')
                w.write(line)
        finally:
           w.close()

def split_file_ex(file_to_split, partitions):
    file_no_lines = sum(1 for line in open(file_to_split))
    partitions_no_lines = int(file_no_lines/partitions)
    file_dir = os.path.dirname(file_to_split)
    split_file(file_to_split, partitions_no_lines)

def run_cmd(script, url_list, partitions):
   #Ref: https://shuzhanfan.github.io/2017/12/parallel-processing-python-subprocess/
   '''
   cmds_list = []
   for x in range(1, partitions+1): 
       cmds_list.append([script, url_list + '_' + str(x)])
   procs_list = [Popen(cmd, stdout=PIPE, stderr=PIPE) for cmd in cmds_list]
   for proc in procs_list:
      proc.wait()
   '''
   for x in range(1, partitions+1):
       cmd_str = script + ' ' + url_list + '_' + str(x) + ' &'
       #https://stackoverflow.com/questions/1196074/how-to-start-a-background-process-in-python
       os.system(cmd_str)


def main():
  url_list = ""
  partitions = 8

  '''
  if len(sys.argv) < 2:
     print("Input url_list file not passed as arguement")
     print_usage()
     sys.exit(0)
  else:
     url_list = sys.argv[1]
     if not os.path.exists(url_list):
        print("url_list: " + url_list + " does not exist")
        print_usage()
        sys.exit(0)
     split_file_ex(url_list, partitions)
  '''
  time_yesterday = datetime.now().timestamp() - 2*60*60*24
  date_yesterday = time.strftime('%d%m%y', time.localtime(time_yesterday))
  url_list =  "/mnt/extra1/projects/phishing/scripts_m3/url_lists/list_" +  str(date_yesterday)
  split_file_ex(url_list, partitions)

  script = '/mnt/extra1/projects/phishing/scripts_m3/collect_data.py'
  run_cmd(script, url_list, partitions)

### MAIN ###
if __name__ == "__main__":
    main()



