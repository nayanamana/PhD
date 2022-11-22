from bs4 import BeautifulSoup
import requests
import sys
import sqlite3
import json

def main():
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute(''' SELECT file_name,trackers from StaticAnalyzer_staticanalyzerandroid ''')
    tracker = c.fetchall()
    tracker_function(tracker)
    c.execute(''' SELECT file_name,Permissions from StaticAnalyzer_staticanalyzerandroid ''')
    permissions= c.fetchall()
    permission_function(permissions)
    c.execute(''' select file_name,firebase_urls from StaticAnalyzer_staticanalyzerandroid where firebase_urls like '%true%' ''')
    firebase_url = c.fetchall()
    firebase_function(firebase_url)
    conn.close()
    
def write_file(file_name,apk_name,data):
    outF = open(file_name, "a")
    outF.write(apk_name+"|"+data)
    outF.write("\n")
    outF.close()
def firebase_function(input_file):
    firebase_url=input_file
    for y in range(len(firebase_url)):
        z=firebase_url[y][1]
        json_acceptable_string = z.replace("'", "\"")
        z=eval(z)
        write_file("firebase_vuln.txt",firebase_url[y][0],z[0]["url"])
def tracker_function(input_file):
    tracker=input_file
    for y in range(len(tracker)):
        z=tracker[y][1]
        json_acceptable_string = z.replace("'", "\"")
        d = json.loads(json_acceptable_string)
        if len(d["trackers"]) >0:
            trackers=list(d["trackers"][0].keys())
            for x in range(len(trackers)):
                write_file("trackers.txt",tracker[y][0],trackers[x])
def permission_function(input_file):
    permission = input_file
    for y in range(len(permission)):
        z=permission[y][1]
        json_acceptable_string = z.replace("'", "\"")
        d = eval(z)
        for p_name, p_info in d.items():
            if d[p_name]["status"] == "dangerous":
                write_file("dangerous_permissions.txt",permission[y][0],p_name)
if __name__ == '__main__':
    main()
