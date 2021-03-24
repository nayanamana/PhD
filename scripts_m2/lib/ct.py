import warnings
warnings.filterwarnings('ignore')

import sys, os, json
import subprocess
import traceback
from datetime import datetime
import time
from datetime import timezone
import re
import requests as reqs

import csv
import glob

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import mysql.connector
from mysql.connector import Error

from collections import OrderedDict
import base64
import io
import zipfile

import requests
#Ref: https://code-maven.com/python-timeout
import signal
#Ref: https://stackoverflow.com/questions/19080792/run-separate-processes-in-parallel-python
from multiprocessing import Pool

from pytz import timezone
tz = timezone('EST')

pghost = "crt.sh"
db = "certwatch"
postgres_user = "guest"

def extract_domain_cert(dom):
   global pghost
   global db
   global postgres_user

   #print("Extracting domain certificate for domain: " + dom)

   query = "SELECT row_to_json(u) FROM (SELECT certificate_id, issuer_ca_id, x509_commonName(certificate) as common_name, x509_issuerName(certificate) as issuer_name, x509_notBefore(certificate) as not_before, x509_notAfter(certificate) as not_after, x509_keyAlgorithm(certificate) as key_algorithm, x509_keySize(certificate) as key_size, x509_serialNumber(certificate) as serial_number, x509_signatureHashAlgorithm(certificate) as signature_hash_algorithm, x509_signatureKeyAlgorithm(certificate) as signature_key_algorithm, x509_subjectName(certificate) as subject_name, x509_name(certificate) as name, x509_altNames(certificate) as alt_names FROM (SELECT certificate_id, certificate, issuer_ca_id FROM certificate_and_identities cai WHERE plainto_tsquery('certwatch', '" + dom + "') @@ identities(cai.CERTIFICATE) AND cai.NAME_VALUE ILIKE ('" + dom + "') AND cai.name_type='san:dNSName' LIMIT 10000) n order by n.certificate_id DESC LIMIT 1) u;"

   cmd = '/usr/bin/psql -t -h ' + pghost + ' -p 5432 -U ' + postgres_user + ' -d ' + db + ' -c "' + query + '"'
   #print("Running command => " + cmd)
   output = ""
   try:
      output = subprocess.getoutput(cmd)
      time.sleep(1)
   except Exception as e:
      traceback.print_exc(file=sys.stdout)
      pass
   #print(output)
   return output

