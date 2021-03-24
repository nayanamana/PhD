#!/usr/local/bin/python3.8

import warnings
import sys, os, json
warnings.filterwarnings('ignore')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import process_url
from extract_URL import Extractor
from website import Website
#from website_fetcher import WebsiteFetcher
#import ofh_save_page

import build_fv

def main():
   ##out_page_dir = '/mnt/extra1/projects/phishing/scripts_m2/webpage_out_b'
   ##url = 'https://mydesk.morganstanley.com'
   #url = "https://cbc.ca"
   '''
        path = '/mnt/extra1/projects/phishing/scripts_m2/webpage_sources'
        sys.setrecursionlimit(10000)
        websitedir = os.path.abspath(path)
        extractor = Extractor()
        label = 'phish' #int(sys.argv[3])
        feat_vec_temp = {}
        #print(brands)



        i = 0

        #pd.set_option('display.max_rows', 1000)

        #time_stats = open("timestats2.csv",'w', encoding="utf8")



        for f in sorted(os.listdir(websitedir)):
            #start_time = current_milli_time()

            if f.find(".json") > 0:
             print(websitedir + "/" + f)
             ws = Website(jspath=websitedir + "/" + f)
             #intermediate = current_milli_time()
             feat_vect_site = build_fv.feature_vector(extractor,ws)
             #end_time = current_milli_time()
             #time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
             feat_vect_site["start_url"] = f
             feat_vect_site["label"] = label
             feat_vec_temp[i] = feat_vect_site
             i += 1
             print(ws.starturl)
        print(feat_vec_temp)
   '''

   #url = 'https://mydesk.morganstanley.com'
   #url = 'http://www.lankapage.com/index_new.php'
   url = "ebay.com"
   #dom = 'ebay.com'
   dom = "mydesk.morganstanley.com"
   #dom = 'google.com'
   ###fetcher = WebsiteFetcher(confirm=True)
   ###fetcher.fetch_and_save_data(url)
   dirname = '/mnt/extra1/projects/phishing/scripts_m2/p1'
   is_phish = 1
   process_url.fetch_and_save_data(dom,dirname)

### MAIN ###
if __name__ == "__main__":
    main()

