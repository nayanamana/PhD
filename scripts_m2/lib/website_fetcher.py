#!/usr/local/bin/python3.8

import os, re, sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

# Authors:   Kalle Saari kalle.saari@aalto.fi, Samuel Marchal samuel.marchal@aalto.fi
# Copyright 2015 Secure Systems Group, Aalto University, https://se-sy.org/
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module is used for downloading data from a website. It uses Firefox
to render the page and takes a screenshot. It is disruptive in that it
forcefully kills all Firefox instantiations in a host after a download is
completed or the program has crashed.  This essentially renders the computer
unusable for the duration of the download.

Can also be used via command line as
    $ python website_fetcher.py www.huawei.com

See the bottom of the file.
"""



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

#############################
# Parameters. Modify these! #
#############################

# path to a Firefox log file
#FFLOG = "/Users/marchas1/Desktop/firefox_log.txt"
FFLOG = os.path.abspath("./firefox_log1.txt.moz_log")
#FFLOG = os.path.abspath("./firefox_log1.txt")
if os.path.exists(FFLOG):
    os.remove(FFLOG)

# Default root for storing sitedata
#DLROOT = "/Users/marchas1/Desktop/"
DLROOT = os.path.abspath(".")



class WebsiteFetcher(object):
    """
    Class for downloading site data. The following information is stored in a
    json file (subject to change):

        - "starturl":  the url given to the fetcher
        - "landurl": landing url (may differ from start url in case of
          redirections)
        - "title"
        - "source": html source of the rendered page
        - "text": text content obtained from the DOM under <body> (hence does
          not include title)
        - "loglinks": urls that Firefox contant while rendering the page
        - "external_sources": if Firefox downloads an html or php page, the
          content of those page is also stored
        - "access_time": time the website was accessed
        - "siteid": an sha1 hash computed from the downloaded data.

    Furthermore, a screenshot of the rendered page is saved as png file.

    IMPORTANT: You have to set up a couple of enviroment variables so that Firefox's
    loglinks are stored. You are reminded of this when instantiating
    WebsiteFetcher object, but you have to change the FFLOG variable within
    this file.
    """

    #Ref: https://wiki.mozilla.org/MailNews:Logging
    def __init__(self, confirm=True):
        #log_help = "\nexport MOZ_LOG=timestamp,nsHttp:5,nsSocketTransport:5,nsStreamPump:5,nsHostResolver:5\n"
        log_help = "\nexport MOZ_LOG=timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:5\n"
        log_help += "export MOZ_LOG_FILE={}\n".format(FFLOG)

        os.environ['MOZ_LOG'] = str('timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:5')
        os.environ['MOZ_LOG_FILE'] = "{}".format(FFLOG)

        print(log_help)

        '''
        if confirm:
            print(log_help)
            ans = input("Have you set the environment variables for Firefox httplogging [y]? ")
            print()
            if ans != 'y':
                sys.exit(0)
        '''

        self.logger = logging.getLogger('spam_application')

    def _kill_firefox(self):
        """
        Kill  **all** Firefox instances
        """
        os.system("""kill -9 `ps -ef | awk '/firefox/{print $2}'`""")

    def fetch_sitedata_and_screenshot(self, url):
        """
        Fetch and sitedata and screenshot.

        Parameters
        ----------
        url: string
            URL of the website

        Returns
        -------
        sitedata: dict
            contains textual data extracted from a site
        screenshot: bytes or None
            binary for the screenshot
        """
        sitedata = {}

        if os.path.exists(FFLOG):
           os.remove(FFLOG) 

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            starturl = 'http://' + url
        else:
            starturl = url

        sitedata['starturl'] = starturl

        headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:32.0) Gecko/20100101 Firefox/32.0',}
        try:
            r = requests.get(starturl, headers=headers, timeout=5)
            landurl = r.url
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            self.logger.info("error in requesting url with requests: {}".format(sys.exc_info()[0]))
            sitedata['redirections'] = []
        else:
            redirections = [link.url for link in r.history]
            sitedata['redirections'] = redirections
            for rdir in redirections:
                self.logger.info(rdir, nots=True)

        # clean Firefox log file
        with open(FFLOG, 'w') as f:
            f.write('')

        options = Options()
        #options.set_headless(headless=True)
        options.headless = True
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(20)

        try:
            driver.maximize_window()
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            driver.quit()
            self._kill_firefox()
            self.logger.info("error in maximizing  window:", sys.exc_info()[0])

        try:
            driver.get(starturl)
            time.sleep(5)
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            print(str(e))
            traceback.print_exc(file=sys.stdout)
            driver.quit()
            self._kill_firefox()
            self.logger.info("FATAL error in fetching landing url with webdriver:", sys.exc_info()[0])
            return {}, None

        try:
            WebDriverWait(driver, 5).until(EC.alert_is_present(),
                                   'Timed out waiting for PA creation ' +
                                   'confirmation popup to appear.')

            alert = driver.switch_to_alert()
            alert.accept()
            print("alert accepted")
        #except TimeoutException:
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            #print("no alert")
            print(str(e))

        try:
            landurl = driver.current_url
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            driver.quit()
            self._kill_firefox()
            self.logger.info("FATAL error in fetching landing url with webdriver:", sys.exc_info()[0])
            return {}, None

        sitedata['landurl'] = landurl

        try:
            screenshot = driver.get_screenshot_as_png()
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            driver.quit()
            self._kill_firefox()
            self.logger.info("FATAL Error in saving a screenshot: {}".format(sys.exc_info()[0]))
            return {}, None

        try:
            title = driver.title
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            self.logger.info("error in saving title: {}".format(sys.exc_info()[0]))
        sitedata['title'] = title

        try:
            source = driver.page_source
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            driver.quit()
            self._kill_firefox()
            self.logger.info("FATAL Error in saving html source: {}".format(sys.exc_info()[0]))
            return {}, None
        sitedata['source'] = source

        try:
            elem = driver.find_element_by_tag_name('body')
            text = elem.text
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            self.logger.info("error in extracting content text: {}".format(sys.exc_info()[0]))
            text = ''
        sitedata['text'] = text

        try:
            driver.quit()
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            # self.logger.info("problem while trying to quit the driver: {}".format(sys.exc_info()[0]))
            self._kill_firefox()

        # extract links from firefox log
        loglinks = set()
        try:    # UnicodeDecodeError
            print("FFLOG: " + FFLOG)
            with open(FFLOG, 'r') as f:
                logtext = f.read()
                for match in re.finditer(r"uri=(http.+)\]", logtext):
                    uri = match.group(1)
                    loglinks.add(uri)
            sitedata['loglinks'] = sorted(loglinks)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            print("error")
            sitedata['loglinks'] = []

        # fetching source from external html and php pages
        found = False
        sitedata['external_source'] = {}
        for ext_url in loglinks:
            if ext_url.endswith('.php') or ext_url.endswith('.html'):
                # this ugly arrangement ensures that Firefox is launched only if needed
                driver_e = None
                if not found:
                    driver = webdriver.Firefox(options=options)
                    driver.set_page_load_timeout(5)
                    found = True
                try:
                    driver.get(ext_url)
                    # time.sleep(2)
                    source = driver.page_source
                    sitedata['external_source'][ext_url] = source
                #except (KeyboardInterrupt, SystemExit):
                #    raise
                except Exception as e:
                    self.logger.info("failed")
                    print(str(e))
                    traceback.print_exc(file=sys.stdout)
                finally:
                    try:
                       driver.quit()
                    except Exception as e1:
                       traceback.print_exc(file=sys.stdout)
                       print(str(e1))

        sitedata['access_time'] = time.ctime()
        try:
            driver.quit()
        #except (KeyboardInterrupt, SystemExit):
        #    raise
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print(str(e))
            # self.logger.info("problem while trying to quit the driver: {}".format(sys.exc_info()[0]))
            self._kill_firefox()
        siteid = hashlib.sha1((sitedata['starturl'] + sitedata['landurl'] + sitedata['source']).encode()).hexdigest()
        sitedata['siteid'] = siteid
        return sitedata, screenshot

    def save_data(self, sitedata, screenshot, dlroot=None):
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

        if dlroot is None:
            dlroot = DLROOT
        # ensure that websites directory exist
        dirname = os.path.join(dlroot, 'websites')
        if not os.path.exists(dirname):
            os.mkdir(dirname)
        jspath = os.path.join(dirname, sitedata['siteid'] + '.json')
        sspath = os.path.join(dirname, sitedata['siteid'] + '.png')

        with open(jspath, 'w') as f:
            json.dump(sitedata, f, indent=0, sort_keys=True)
        with open(sspath, 'wb') as f:
            f.write(screenshot)
        return jspath, sspath

    def fetch_and_save_data(self, url, dlroot=None):
        """
        Fetch and save data from a give url.
        
        This function simply combines `etch_sitedata_and_screenshots() and
        save_data(). Look at theis doc strings for further info.
        """
        sitedata, screenshot = self.fetch_sitedata_and_screenshot(url)
        print(sitedata)
        if not sitedata:
            self.logger.info("failed to fetch url")
            return '', ''
        jspath, sspath = self.save_data(sitedata, screenshot, dlroot=dlroot)
        print(jspath)
        print(sspath)
        return jspath, sspath


if __name__ == '__main__':
    usage = 'usage:\n\tpython {} <url>'
    if not sys.argv[1:]:
        print(usage)
    else:
        url = sys.argv[1]
        fetcher = WebsiteFetcher(confirm=True)
        fetcher.fetch_and_save_data(url)

