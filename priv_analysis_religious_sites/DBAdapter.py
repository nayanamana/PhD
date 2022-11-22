import sqlite3
from sqlite3 import Error


class HospitalDBAdpater:
    def __init__(self, db_file):
        self._conn = self._create_conn(db_file)
        self.db_file = db_file

    def _create_conn(self, db_file):
        conn = None
        try:
            conn = sqlite3.connect(db_file)
        except Error as e:
            print(e)

        return conn


    def get_script_file_from_javascript(self):
        query = 'SELECT DISTINCT script_file, top_level_url FROM javascript' \
                ' WHERE INSTR(first_party_host, third_party_domain)=0 GROUP BY top_level_url'
        cursor = self._conn.execute(query)
        total = 0
        scripts_list = []
        for row in cursor:
            total = total + 1
            script, top_url = row[0], row[1]
            script = "http://" + script
            item = {}
            item['tp_url'] = script
            item['top_url'] = top_url
            scripts_list.append(item)
            # print(row)
        return scripts_list


    def get_cookies_from_js_cookies(self):
        query = 'SELECT distinct name, host, first_party_host FROM javascript_cookies ' \
        ' WHERE INSTR(first_party_host, third_party_domain)=0 GROUP BY first_party_host, third_party_domain, name'

        cursor = self._conn.execute(query)
        total = 0
        cookies_list = []
        for row in cursor:
            total = total + 1
            tp_host, first_party_host = row[1], row[2]
            if tp_host.startswith('.'):
                tp_host =  tp_host[1: ]
            cookie = {}
            cookie['tp_host'] = "http://" + tp_host
            cookie['top_url'] = "http://" + first_party_host
            cookies_list.append(cookie)
        return cookies_list


# ***********************************************COOKIE******************************************************************
    #     keyword = ['collect', 'collectInfo', 'collectUserVisitInfoAndSendToServer',
    #                'autoTrack', 'allowTrack', 'AddTrackerCount', 'urchinTracker', 'reportToBoss',
    #                 'getAllUserInfo', 'exports.initSensorSDK', 'setCookieForClick', 'walkAndCount']

def get_content_type(headers):
    headers = headers[1: -1]
    header_list = []
    start = -1
    start = headers.find('Content-Type",')
    if start==-1:
        start = headers.find('content-type",')
    if start==-1:
        return ''

    item = headers[start:].split(']')[0]
    content_type = item.split(',')[1]
    if ';' in content_type:
        content_type = content_type.split(';')[0]

    return content_type


