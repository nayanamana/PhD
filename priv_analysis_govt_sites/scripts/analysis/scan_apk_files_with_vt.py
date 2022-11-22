#!/usr/local/bin/python3.8

import warnings
import os, sys, json, csv, glob, re
import os.path
import tldextract
from virustotal_python import Virustotal
from pprint import pprint
import time
import requests
import datetime
import traceback


# You can provide True to the `COMPATIBILITY_ENABLED` parameter to preserve the old response format of virustotal-python versions prior to 0.1.0
vt_key = <VIRUSTOTAL API KEY>
vtotal = Virustotal(API_KEY=vt_key, API_VERSION="v3") #, COMPATIBILITY_ENABLED=True)

out_dir = '/tmp/output'

def get_datetime():
    now = datetime.datetime.now()
    return str(now.strftime("%Y-%m-%d %H:%M:%S"))

#Ref: https://pypi.org/project/virustotal-python/
def check_with_vt(country, apk, apk_path, of, off, log):
   global vtotal
   scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
   scan_params = {'apikey': vt_key}

   status = "PASSED"
   engine_result = {'no': 0, 'eng_list': [], 'result_list': []}

   try:
      files = {'file': (apk_path, open(apk_path, 'rb'))}
      scan_request = requests.post(scan_url, files=files, params=scan_params)

      time.sleep(3) #give sufficient time to get scan id
      scan_id = scan_request.json().get('md5')
      pprint(scan_request.json())

      if scan_request.status_code != 200:
          print(f"Error. [{scan_request.status_code}]")
      else:


           report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
           report_params = {'apikey': vt_key, 'resource': scan_id, 'allinfo': True}
           report_response = requests.get(report_url, params=report_params)

           response_json = report_response.json()
           response_json_obj = response_json # json.loads(response_json)
           off.write(str(json.dumps(response_json)) + "\n")
           off.flush()

           scans = response_json_obj['scans']
           for eng in scans:
               eng_res = scans[eng]
               is_detected = eng_res['detected']
               result = eng_res['result']
               if is_detected:
                   engine_result['no'] += 1
                   engine_result['eng_list'].append(eng)
                   engine_result['result_list'].append(result)

   except Exception as e:
           traceback.print_exc(limit=2, file=sys.stdout)
           print("FAILED : "  + str(e))
           status = "FAILED : " + str(e)

   str2 = str(country) + '|' + str(apk) + '|' + str(engine_result['no']) + '|' + json.dumps(engine_result['eng_list']) + '|' + json.dumps(engine_result['result_list'])
   of.write(str2 + "\n")
   of.flush()

   log_str = get_datetime() + "|" + str(country) + '|' + str(apk) + '|' + status
   log.write(log_str + "\n")
   log.flush()




def process_apks(apk_root_dir):
    apk_country_map = {}
    for country_path in glob.glob(apk_root_dir + '/*'):

        country_str = os.path.basename(country_path).lower()
        count = 0
        for _, _, files in os.walk(country_path):
            apk_path = country_path
            for f in files:

                if f not in apk_country_map:
                    apk_country_map[f] = {'country_path': apk_path, 'country': country_str}

    return apk_country_map

def scan_with_vt(apk_root_dir, of, off, log):
    global out_dir
    apk_country_map = process_apks(apk_root_dir)


    for apk in apk_country_map:
        val = apk_country_map[apk]
        country = val['country']
        country_path = val['country_path']
        apk_path = country_path + "/" + apk
        check_with_vt(country, apk, apk_path, of, off, log)



def main():
    apk_root_dir = '/tmp/collected_apks'

    of = open(out_dir + "/vt_dump.txt", "w+")
    off = open(out_dir + "/vt_dump_full.txt", "w+")
    log = open(out_dir + "/vt_dump_log.txt", "w+")

    scan_with_vt(apk_root_dir, of, off, log)

    of.close()
    off.close()
    log.close()



if __name__ == '__main__':
    main()
