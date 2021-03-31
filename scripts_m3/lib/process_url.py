#!/usr/local/bin/python3.8

import os, re, sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

import hashlib
import json
import os
import re
import requests
import logging
import sys
import time
import urllib

import traceback

from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from selenium.webdriver.firefox.options import Options

from requests_html import HTMLSession

from signal import signal, SIGINT
from sys import exit

import datetime

logger = logging.getLogger('phishing')

#############################
# Parameters. Modify these! #
#############################

# path to a Firefox log file
#FFLOG = "/Users/marchas1/Desktop/firefox_log.txt"
#FFLOG = os.path.abspath("./firefox_log.txt")

# Default root for storing sitedata
#DLROOT = "/Users/marchas1/Desktop/"
#pid = os.getpid()
#ppid = os.getppid()
#print("### " + str(pid) + ' -- ' + str(ppid))

#FFLOG = os.path.abspath("./ff_log/firefox_log_" + str(pid) + ".txt.moz_log")
#if os.path.exists(FFLOG):
#    os.remove(FFLOG)

#os.environ['MOZ_LOG'] = str('timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:5')
#os.environ['MOZ_LOG_FILE'] = "{}".format(FFLOG)

DLROOT = os.path.abspath(".")

def print_time():
   print(datetime.datetime.now().time())

def purge_ff_log(pattern):
    dir_name = "/mnt/extra1/projects/phishing/scripts_m3/ff_log/"
    for f in os.listdir(dir_name):
        if re.search(pattern, f):
            os.remove(os.path.join(dir_name, f))

def _kill_firefox():
     """
     Kill  **all** Firefox instances
     """
     os.system("""kill -9 `ps -ef | awk '/firefox/{print $2}'`""")

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    _kill_firefox()
    #purge_ff_log("firefox_log.txt.moz_log_" + str(pid))
    purge_ff_log("firefox_log")
    exit(0)

def fetch_sitedata_and_screenshot(domain, dirname):
        #global pid
        pid = os.getpid()

        root_dir = "/mnt/extra1/projects/phishing/scripts_m3/"
     
        #FFLOG = os.path.abspath("/mnt/extra1/projects/phishing/scripts_m3/ff_log/firefox_log.txt.moz_log_" + str(pid))
        FFLOG = os.path.abspath(root_dir + "./ff_log/firefox_log_" + str(pid) + ".txt.moz_log")
        if os.path.exists(FFLOG):
           os.remove(FFLOG)

        os.environ['MOZ_LOG'] = str('timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:5')
        os.environ['MOZ_LOG_FILE'] = "{}".format(FFLOG)

        #If domain contains IP, return 
        re_ip = re.search('\d+?\.\d+?\.\d+?\.\d+?', domain)
        if re_ip:
           return {}, None

        code = 999
        headers = {'use-agent': 'Mozilla/5.0 (X11; Linux i686; rv:86.0) Gecko/20100101 Firefox/86.0'}
        if '://' in domain:
           try:
              url = domain
              session = HTMLSession(verify=False)
              r = session.get(url, headers=headers, timeout=20)    
              code = r.status_code
           except Exception as e:
              #traceback.print_exc(limit=2, file=sys.stdout)
              #print(str(e))
              return {}, None
        else:
           is_https = 0
           url = 'https://' + domain
           r = None
   
           try:
              url = 'https://' + domain
              #print("ZZZZZZ: " + url)
              #Ref: https://stackoverflow.com/questions/56691190/requests-html-httpsconnectionpoolread-timed-out
              session = HTMLSession(verify=False)
              r = session.get(url, headers=headers, timeout=20)
              code = r.status_code
              is_https = 1
           except Exception as e:
              #traceback.print_exc(limit=2, file=sys.stdout)
              #print(str(e))
              return {}, None

           if is_https == 0:
              try:
                 url = 'http://' + domain
                 session = HTMLSession(verify=False)
                 r = session.get(url, headers=headers, timeout=20)
                 code = r.status_code
              except Exception as e:
                 #traceback.print_exc(limit=2, file=sys.stdout)
                 #print(str(e))
                 #print("ERROR: Failed to browse URL: " + url + " --- from HTMLSession")
                 return {}, None

        if code != 200:
            return {}, None

        sitedata = {}

        if os.path.exists(FFLOG):
           os.remove(FFLOG)

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            starturl = 'http://' + url
        else:
            starturl = url

        sitedata['starturl'] = starturl
        #print("START URL: " + starturl)

        #print("222")
        #print_time()

        headers = {'use-agent': 'Mozilla/5.0 (X11; Linux i686; rv:86.0) Gecko/20100101 Firefox/86.0'}
        try:
            landurl = r.url
        except Exception as e:
            traceback.print_exc(limit=2, file=sys.stdout)
            print(str(e))
            sitedata['redirections'] = []
        else:
            redirections = [link.url for link in r.history]
            sitedata['redirections'] = redirections
            for rdir in redirections:
                logger.info(rdir, nots=True)

        # clean Firefox log file
        with open(FFLOG, 'w') as f:
            f.write('')

        #############################################################
        ### Measurements using Selenium
        ############################################################
        #print("333")
        #print_time()

        try:
            options = Options()
            options.headless = True
            driver = webdriver.Firefox(options=options)
            driver.set_page_load_timeout(20)

        
            driver.maximize_window()
            driver.get(starturl)
            ###time.sleep(5)
        
            '''
            try:
               WebDriverWait(driver, 5).until(EC.alert_is_present(),
                                   'Timed out waiting for PA creation ' +
                                   'confirmation popup to appear.')

               alert = driver.switch_to_alert()
               alert.accept()
               print("alert accepted")
            except Exception as e:
               traceback.print_exc(limit=2, file=sys.stdout)
               print(str(e))
            '''
       
            landurl = driver.current_url
            sitedata['landurl'] = landurl
            logger.info("FATAL error in fetching landing url with webdriver:", sys.exc_info()[0])
            #return {}, None
            screenshot = driver.get_screenshot_as_png()
            title = driver.title
            sitedata['title'] = title
            source = driver.page_source
            sitedata['source'] = source

            elem = driver.find_element_by_tag_name('body')
            text = elem.text
            sitedata['text'] = text
        except Exception as e:
            traceback.print_exc(limit=2, file=sys.stdout)
            print(str(e))
            return {}, None
        finally:
            try:
               driver.quit()
            except Exception as e:
               pass
            #try:
            #   _kill_firefox()
            #except Exception as e:
            #   pass
        
        #print("4444")
        #print_time()
        
        # extract links from firefox log
        loglinks = set()
        try:    # UnicodeDecodeError
            with open(FFLOG, 'r') as f:
                logtext = f.read()
                #print('-----------------------')
                #print(logtext)
                for match in re.finditer(r"uri=(http.+)\]", logtext):
                    uri = match.group(1)
                    loglinks.add(uri)
            sitedata['loglinks'] = sorted(loglinks)
        except Exception as e:
            traceback.print_exc(limit=2, file=sys.stdout)
            print(str(e))
            print("error")
            sitedata['loglinks'] = []

        # fetching source from external html and php pages
        found = False
        sitedata['external_source'] = {}
        for ext_url in loglinks:
            if ext_url.endswith('.php') or ext_url.endswith('.html'):
                # this ugly arrangement ensures that Firefox is launched only if needed
                try:
                   if not found:
                      driver = webdriver.Firefox(options=options)
                      driver.set_page_load_timeout(5)
                      found = True
                
                   driver.get(ext_url)
                   source = driver.page_source
                   sitedata['external_source'][ext_url] = source
                except Exception as e:
                    #traceback.print_exc(limit=2, file=sys.stdout)
                    #print(str(e))
                    pass
                finally:
                    try:
                        driver.quit()
                    except Exception as e:
                        pass
                    #try:
                    #    _kill_firefox()
                    #except Exception as e:
                    #     pass

        #print("555")
        #print_time()

        sitedata['access_time'] = time.ctime()
        siteid = hashlib.sha1((sitedata['starturl'] + sitedata['landurl'] + sitedata['source']).encode()).hexdigest()
        sitedata['siteid'] = siteid

        purge_ff_log("firefox_log_" + str(pid) + ".txt.moz_log")

        #print(sitedata)
        return sitedata, screenshot

def get_web_domain(url):
       re_dom = re.search('://(.+?)/', url)
       dom = ""
       if re_dom:
          dom = re_dom.group(1)
       else:
          re_dom = re.search('://(.+)', url)
          if re_dom:
             dom = re_dom.group(1)
       return dom

#def save_data(self, sitedata, screenshot, dlroot=None):
def save_data(url, sitedata, screenshot, dirname):
        """
        Save the data obtained from the output of the function
        fetch_sitedata_and_screenshot().

        Parameters
        ----------
        sitedata: json object
        screenshot: binary png
        dlroot: string or None
            Path to the root in which the data is to be stored. The files are
            saved in the following paths: jspath: dlroot/sitedata/<siteid>.json
            sspath: dlroot/screenshots/<siteid>.png If not given, dlroot is set
            to DLROOT

        Returns
        -------
        jspath: str
            path to the json file
        sspath: str
            path to the screenshot file
        """
        # OLD DOWNLOAD SCHEME. OK TO DELETE
        # # ensure that sitedata and screenshots directories exist
        # dirname = os.path.join(dlroot, 'sitedata')
        # if not os.path.exists(dirname):
        #     os.mkdir(dirname)
        # dirname = os.path.join(dlroot, 'screenshots')
        # if not os.path.exists(dirname):
        #     os.mkdir(dirname)
        # jspath = os.path.join(dlroot, 'sitedata', sitedata['siteid'] + '.json')
        # sspath = os.path.join(dlroot, 'screenshots', sitedata['siteid'] + '.png')

        #if dlroot is None:
        #    dlroot = DLROOT
        # ensure that websites directory exist
        #dirname = os.path.join(dlroot, 'websites')
        if not os.path.exists(dirname):
            os.mkdir(dirname)
        #print("DIR: " + dirname)
        dom = get_web_domain(url)
        dom = dom.replace('www.','')
        #jspath = os.path.join(dirname, sitedata['siteid'] + '.json')
        #sspath = os.path.join(dirname, sitedata['siteid'] + '.png')
        jspath = os.path.join(dirname, dom + '.json')
        sspath = os.path.join(dirname, dom + '.png')

        #print(jspath)

        with open(jspath, 'w') as f:
            json.dump(sitedata, f, indent=0, sort_keys=True)
        with open(sspath, 'wb') as f:
            f.write(screenshot)
        return jspath, sspath

#def fetch_and_save_data(self, url, dlroot=None):
def fetch_and_save_data(url, is_phish, dirname):
        """
        Fetch and save data from a give url.

        This function simply combines `etch_sitedata_and_screenshots() and
        save_data(). Look at theis doc strings for further info.
        """

        # Tell Python to run the handler() function when SIGINT is recieved
        signal(SIGINT, handler)

        sitedata, screenshot = fetch_sitedata_and_screenshot(url, dirname)
        #print(sitedata)
        if not sitedata:
            logger.info("failed to fetch url")
            return '', ''

        sitedata['is_phish'] = is_phish
        #jspath, sspath = save_data(sitedata, screenshot, dlroot=dlroot)
        jspath, sspath = save_data(url, sitedata, screenshot, dirname)
        return jspath, sspath




