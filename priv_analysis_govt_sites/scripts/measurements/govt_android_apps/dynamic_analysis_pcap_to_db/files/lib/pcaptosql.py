from __future__ import print_function
import sqlite3
import csv
import sys
import re
import time,os
import sys
import whois
import json
import subprocess
import urllib
#from http import cookies
from shutil import copyfile
from publicsuffix import PublicSuffixList
import requests

from publicsuffix import fetch
from IPy import IP
import socket
from urllib.parse import urlparse
import os
from shutil import copyfile
import shutil
import tldextract
#from whotracksme.data.loader import DataSource
from collections import defaultdict
from urllib.parse import unquote
import hashlib
import base64
from time import time
#------------------------------
# addhashes
#-----------------------------    

def addhashes():



        curDest.execute(" select distinct key,tag,desc, device_related, partialmatch"
                        " from leak_category"
                        " where  active = 1  and hash = 0 ") # and crawl_id=" + hotspot_params["crawl_id"] )

        rows = curDest.fetchall()
        for row in rows:
                F_value = row[1]


                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.md5(F_value.encode()).hexdigest(),str(row[2])  + 'md5'+ "--" + str(row[1]),row[3],row[4],1,1))

                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha512(F_value.encode()).hexdigest(),str(row[2])  + 'sha512'+ "--" + str(row[1]),row[3],row[4],1,1))


                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha256(F_value.encode()).hexdigest(),str(row[2])  + 'sha256'+ "--" + str(row[1]),row[3],row[4],1,1))


                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.blake2b(F_value.encode()).hexdigest(),str(row[2])  + 'blake2b'+ "--" + str(row[1]),row[3],row[4],1,1))

                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.blake2s(F_value.encode()).hexdigest(),str(row[2])  + 'blake2s'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha1(F_value.encode()).hexdigest(),str(row[2])  + 'sha1'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha224(F_value.encode()).hexdigest(),str(row[2])  + 'sha224'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha384(F_value.encode()).hexdigest(),str(row[2])  + 'sha384'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha3_224(F_value.encode()).hexdigest(),str(row[2])  + 'sha3_224'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha3_256(F_value.encode()).hexdigest(),str(row[2])  + 'sha3_256'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha3_384(F_value.encode()).hexdigest(),str(row[2])  + 'sha3_384'+ "--" + str(row[1]),row[3],row[4],1,1))

                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],hashlib.sha3_512(F_value.encode()).hexdigest(),str(row[2])  + 'sha3_512'+ "--" + str(row[1]),row[3],row[4],1,1))


                encodedBytes = base64.b64encode(F_value.encode("utf-8"))
                encodedStr = str(encodedBytes, "utf-8")
                curDest.execute("insert into  leak_category(key,tag,desc,device_related,partialmatch,active,hash)"
                        " values(?,?,?,?,?,?,?)", (row[0],encodedStr,str(row[2])  + 'base64'+ "--" + str(row[1]),row[3],row[4],1,1))
                
                

                curDest.execute("delete from leak_category"
                        " where rowid not in (select min(rowid)"
                        " from leak_category"
                        " group by key,tag,desc)")


        curDest.execute(" update leak_category"
                        " set target = 'child/parent'"
                        " where  desc like '%child/parent%'"
                        " and target is null;")

        curDest.execute(" update leak_category"
                        " set target = 'parent'"
                        " where  desc like '%parent%'"
                        " and target is null;")


        curDest.execute(" update leak_category"
                        " set target = 'child'"
                        " where  desc like '%child%'"
                        " and target is null;")

        curDest.execute(" select distinct key,tag,desc, device_related, partialmatch"
                        " from leak_category"
                        " where  active = 1  and hash = 0") # and crawl_id=" + hotspot_params["crawl_id"] )

#------------------------------
# isBase64
#-----------------------------                   

def isBase64(sb):
        try:
                if isinstance(sb, str):
                        # If there's any unicode here, an exception will be thrown and the function will return false
                        sb_bytes = bytes(sb, 'ascii')
                elif isinstance(sb, bytes):
                        sb_bytes = sb
                else:
                        raise ValueError("Argument must be string or bytes")
                return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
                return False


#------------------------------
# decodeBase64
#-----------------------------                   

def decodeBase64(sb):
        try:
                if isinstance(sb, str):
                        # If there's any unicode here, an exception will be thrown and the function will return false
                        sb_bytes = bytes(sb, 'ascii')
                        #print (sb_bytes)
                elif isinstance(sb, bytes):
                        sb_bytes = sb
                else:
                        raise ValueError("Argument must be string or bytes")
                if base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes:
                    #print (base64.b64decode(sb_bytes))
                    return str(base64.b64decode(sb_bytes).decode('utf-8'))
        except Exception:
                return ""
                        

#------------------------------
# decodeHttpTrafficBase64
#-----------------------------                   

def decodeHttpTrafficBase64 ():
#    try:

            
            curDest.execute("select distinct decodedvalue"
                        "    from http_profile_cookies  where decodebase64 is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:

                value = row[0]
                if isBase64(value):
                    decodedvalue = decodeBase64(value)
                    curDest.execute("update     http_profile_cookies set decodebase64 = ? where decodedvalue =?", (decodedvalue,value))



            curDest.execute("insert into  base64commoncodes(code,decodedcode)"
                        " select distinct decodedvalue,decodebase64"
                        " from http_profile_cookies where ifnull(decodebase64,'')!= ''  "
                        " and decodedvalue not in (select x.code from base64commoncodes x )")


            curDest.execute("select distinct decodedvalue"
                        "    from http_requests_querystring  where decodebase64 is null")
                                
 
            rows = curDest.fetchall()
            for row in rows:
                value = row[0]
                if isBase64(value):
                    decodedvalue = decodeBase64(value)
                    curDest.execute("update http_requests_querystring  "
                                    " set decodebase64 = ? where decodedvalue =?", (decodedvalue,value,))


            curDest.execute("insert into  base64commoncodes(code,decodedcode)"
                        " select distinct decodedvalue,decodebase64"
                        " from http_requests_querystring where ifnull(decodebase64,'')!= ''   "
                        " and decodedvalue not in (select x.code from base64commoncodes x )")

            curDest.execute("select distinct decodedvalue"
                            "    from http_responses_querystring  where decodebase64 is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                value = row[0]
                if isBase64(value):
                    decodedvalue = decodeBase64(value)
                    curDest.execute("update http_responses_querystring  "
                                    " set decodebase64 = ? where decodedvalue =?", (decodedvalue,value,))
   

            curDest.execute("insert into  base64commoncodes(code,decodedcode)"
                        " select distinct decodedvalue,decodebase64"
                        " from http_responses_querystring where ifnull(decodebase64,'')!= ''   "
                        " and decodedvalue not in (select x.code from base64commoncodes x )")

            curDest.execute("select distinct decodedvalue"
                            "    from http_localstorages  where decodebase64 is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                value = row[0]
                if isBase64(value):
                    decodedvalue = decodeBase64(value)
                    curDest.execute("update http_localstorages  "
                                    " set decodebase64 = ? where decodedvalue =?", (decodedvalue,value,))


            curDest.execute("insert into  base64commoncodes(code,decodedcode)"
                        " select distinct decodedvalue,decodebase64"
                        " from http_localstorages where ifnull(decodebase64,'')!= ''   "
                        " and decodedvalue not in (select x.code from base64commoncodes x )")


            curDest.execute("select distinct decodedvalue"
                        "    from http_referrer_querystring  where decodebase64 is null")
                                
 
            rows = curDest.fetchall()
            for row in rows:
                value = row[0]
                if isBase64(value):
                    decodedvalue = decodeBase64(value)
                    curDest.execute("update http_referrer_querystring  "
                                    " set decodebase64 = ? where decodedvalue =?", (decodedvalue,value,))



            curDest.execute("insert into  base64commoncodes(code,decodedcode)"
                        " select distinct decodedvalue,decodebase64"
                        " from http_referrer_querystring where ifnull(decodebase64,'')!= ''   "
                        " and decodedvalue not in (select x.code from base64commoncodes x )")
 #   except Exception as e:
 #       print(e)


#------------------------------
# decodeHttpTraffic
#-----------------------------                   

def decodeHttpTraffic ():



#copy data to original fields so we can keep original value
            curDest.execute(" update Crawl"
                               " set org_LandingPageUrl = LandingPageUrl "
                               " where org_LandingPageUrl is null ")

            curDest.execute(" update Crawl"
                            " set org_WelcomePageUrl = WelcomePageUrl "
                            " where org_WelcomePageUrl is null ")


            curDest.execute(" update http_requests"
                            " set orgrequest_full_uri = request_full_uri "
                            " where orgrequest_full_uri is null ")


            cnnDestination.commit()
            curDest.execute(" update http_requests"
                            " set orgreferer = referer "
                            " where orgreferer is null ")


            curDest.execute(" update http_requests"
                            " set orgcookie = cookie "
                            " where orgcookie is null ")



            curDest.execute(" update http_requests"
                            " set orgtext = text "
                            " where orgtext is null ")

            curDest.execute(" update http_requests"
                            " set orgjson_file = json_file "
                            " where orgjson_file is null ")


            cnnDestination.commit()

            curDest.execute(" update http_responses"
                            " set orglocation = location "
                            " where orglocation is null ")


            curDest.execute(" update http_responses"
                            " set orgset_cookie = set_cookie "
                            " where orgset_cookie is null ")


            curDest.execute(" update http_responses"
                            " set orgtext = text "
                            " where orgtext is null ")

            curDest.execute(" update http_responses"
                            " set orgjson_file = json_file "
                            " where orgjson_file is null ")


            curDest.execute(" update site_visits"
                            " set orgsite_url = site_url "
                            " where orgsite_url is null ")


            cnnDestination.commit()
            curDest.execute(" update http_profile_cookies"
                            " set orgvalue = value "
                            " where orgvalue is null ")


            curDest.execute(" update http_localstorages"
                            " set orgvalue = value "
                            " where orgvalue is null ")


            curDest.execute(" update DFPM_javascript"
                            " set orgurl = url "
                            " where orgurl is null ")


            curDest.execute(" update DFPM_javascript"
                            " set orgscript_url = script_url "
                            " where orgscript_url is null ")


            curDest.execute(" update http_requests_querystring"
                            " set orgurl = url "
                            " where orgurl is null ")


            curDest.execute(" update http_responses_querystring"
                            " set orgurl = url "
                            " where orgurl is null ")


            curDest.execute(" update http_referrer_querystring"
                            " set orgurl = url "
                            " where orgurl is null ")
            


#start url decode
            curDest.execute("select distinct value"
                        "    from http_profile_cookies  where decodedvalue is null and value is not null")
                                
            rows = curDest.fetchall()

            for row in rows:

                value = row[0]
                decodedvalue = urllib.parse.unquote(value)
                curDest.execute("update     http_profile_cookies set decodedvalue = ? where value =?", (decodedvalue,value))

            curDest.execute("select distinct value"
                        "    from http_requests_querystring  where decodedvalue is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(value)
                    curDest.execute("update http_requests_querystring  "
                                    " set decodedvalue =  ?"
                                    " where value =?", (decodedvalue,value,))





            curDest.execute("select distinct value"
                            "    from http_responses_querystring  where decodedvalue is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(value)
                    curDest.execute("update http_responses_querystring  "
                                    " set decodedvalue =  ?"
                                    " where value =?", (decodedvalue,value,))
   

            curDest.execute("select distinct value"
                            "    from http_localstorages  where decodedvalue is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(value)
                    curDest.execute("update   http_localstorages"
                                    " set decodedvalue =  ?"
                                    " where value =?", (decodedvalue,value,))

            curDest.execute("select distinct value"
                            "    from http_referrer_querystring  where decodedvalue is null")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(value)
                    curDest.execute("update http_referrer_querystring  "
                                    " set decodedvalue =  ?"
                                    " where value =?", (decodedvalue,value,))


            curDest.execute("select distinct id,url"
                        "    from http_requests_querystring ")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(row[1])
                    curDest.execute("update http_requests_querystring  "
                                    " set url =  ?"
                                    " where id =?", (decodedvalue,value,))


            curDest.execute("select distinct id,url"
                        "    from http_responses_querystring ")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(row[1])
                    curDest.execute("update http_responses_querystring  "
                                    " set url =  ?"
                                    " where id =?", (decodedvalue,value,))

            curDest.execute("select distinct id,url"
                        "    from http_referrer_querystring ")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote(row[1])
                    curDest.execute("update http_referrer_querystring  "
                                    " set url =  ?"
                                    " where id =?", (decodedvalue,value,))
##    except Exception as e:
##        print(e)

  

            curDest.execute("select distinct id, url,script_url"
                            "    from DFPM_javascript ")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedurl = urllib.parse.unquote( row[1])
                    decodedscript_url = urllib.parse.unquote( row[1])
                    curDest.execute("update DFPM_javascript  "
                                    " set url =  ?, script_url=?"
                                    " where id =?", (decodedurl,decodedscript_url,value,))


            curDest.execute("select distinct id, site_url"
                            "    from site_visits ")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote( row[1])
                    curDest.execute("update site_visits  "
                                    " set site_url =  ?"
                                    " where id =?", (decodedvalue,value,))




            cnnDestination.commit()
            curDest.execute("select distinct crawl_id, LandingPageUrl,WelcomePageUrl"
                            "    from crawl  ")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue1 = ""
                    decodedvalue2 = ""
                    if  row[1]!= None:
                            decodedvalue1 = urllib.parse.unquote( row[1])
                    if  row[2]!= None:
                            decodedvalue2 = urllib.parse.unquote( row[2])
                    curDest.execute("update crawl  "
                                    " set LandingPageUrl =  ?, WelcomePageUrl=?"
                                    " where crawl_id =?", (decodedvalue1,decodedvalue2,value,))



##    except Exception as e:
##        print(e)

            curDest.execute("select distinct id, request_full_uri, text, json_file, referer, cookie,r_header"
                        "    from http_requests where  request_full_uri = orgrequest_full_uri")
                                
 
            rows = curDest.fetchall()

            for row in rows:

                    value = row[0]
                    decodedurl = ""
                    decodedtext = ""
                    decodedjsonfile = ""
                    decodedreferer = ""
                    decodedcookie = ""
                    decodedrheader = ""
                    if row[1] != None:
                            decodedurl = urllib.parse.unquote(row[1])
                    if row[2] != None:
                            decodedtext = urllib.parse.unquote(row[2])
                    if row[3] != None:
                            decodedjsonfile = urllib.parse.unquote(row[3])
                    if row[4] != None:
                            decodedreferer = urllib.parse.unquote(row[4])
                    if row[5] != None:
                            decodedcookie = urllib.parse.unquote(row[5])
                    if row[6] != None:
                            decodedrheader = urllib.parse.unquote(row[6])
                    curDest.execute("update http_requests  "
                                    " set request_full_uri =  ?, text = ? , json_file = ?, referer = ?, cookie = ?,r_header=?"
                                    " where id =?", (decodedurl,decodedtext,decodedjsonfile,decodedreferer,decodedcookie,decodedrheader,value,))
                    cnnDestination.commit()

            curDest.execute("select distinct id, location, text, json_file,set_cookie,r_header"
                        "    from http_responses  where location = orglocation ")
                                
 
            rows = curDest.fetchall()

            for row in rows:

                    value = row[0]
                    decodedurl = ""
                    decodedtext = ""
                    decodedjsonfile = ""
                    decodedset_cookie = ""
                    decodedrheader = ""
                    if row[1] != None:
                            decodedurl = urllib.parse.unquote(row[1])
                    if row[2] != None:
                            decodedtext = urllib.parse.unquote(row[2])
                    if row[3] != None:
                            decodedjsonfile = urllib.parse.unquote(row[3])
                    if row[4] != None:
                            decodedset_cookie = urllib.parse.unquote(row[4])
                    if row[5] != None:
                            decodedrheader = urllib.parse.unquote(row[5])
                    curDest.execute("update http_responses  "
                                    " set location =  ?, text = ? , json_file = ?, set_cookie = ?, r_header=?"
                                    " where id =?", (decodedurl,decodedtext,decodedjsonfile,decodedset_cookie,decodedrheader,value,))
                    cnnDestination.commit()


#decode  values into base64. 
            decodeHttpTrafficBase64()       

#Replace base64 decoded strings everywhere. We need to manually check the database for the text that we can decode use base64.
#Then ,populate the pair (base64 code, decoded text) in table base64commoncodes (This is a manual step right now, but it could be enhanced


                    
            curDest.execute("select distinct code, decodedcode"
                            "    from base64commoncodes where ifnull(decodedcode,'') !=''  and approved = 1")
                                
 
            rows = curDest.fetchall()

            for row in rows:
                    value = row[0]
                    decodedvalue = urllib.parse.unquote( row[1])
                    curDest.execute("update http_requests  "
                                    " set request_full_uri = replace(request_full_uri,?,  ?)"
                                    " where request_full_uri like ?", (value,decodedvalue,'%'+value+'%',))
                    cnnDestination.commit()



                    curDest.execute("update http_requests  "
                                    " set text = replace(text,?,  ?)"
                                    " where text like ? ", (value,decodedvalue, '%' + value + '%',))
  
                    curDest.execute("update http_requests  "
                                    " set json_file = replace(json_file,?,  ?)"
                                    " where json_file like ?" , (value,decodedvalue, '%' + value + '%',))


                    curDest.execute("update http_requests  "
                                    " set referer = replace(referer,?,  ?)"
                                    " where referer like ?" , (value,decodedvalue, '%' + value + '%',))

                        
                    curDest.execute("update http_requests  "
                                    " set cookie = replace(cookie,?,  ?)"
                                    " where cookie like ?" , (value,decodedvalue, '%' + value + '%',))


                    cnnDestination.commit()
                    curDest.execute("update http_responses  "
                                    " set location = replace(location,?,  ?)"
                                    " where location like ?" , (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update http_responses  "
                                    " set json_file = replace(json_file,?,  ?)"
                                    " where json_file like ?" , (value,decodedvalue, '%' + value + '%',))


                    curDest.execute("update http_responses  "
                                    " set text = replace(text,?,  ?)"
                                    " where text like ?" , (value,decodedvalue, '%' + value + '%',))


                    curDest.execute("update http_responses  "
                                    " set text = replace(text,?,  ?)"
                                    " where text like ?" , (value,decodedvalue, '%' + value + '%',))


                    curDest.execute("update site_visits  "
                                    " set site_url = replace(site_url,?,  ?)"
                                    " where site_url like ?" , (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update DFPM_javascript  "
                                    " set url = replace(url,?,  ?)"
                                    " where url like ?" , (value,decodedvalue, '%' + value + '%',))


                    cnnDestination.commit()
                    curDest.execute("update DFPM_javascript  "
                                    " set script_url = replace(script_url,?,  ?)"
                                    " where script_url like ?" , (value,decodedvalue, '%' + value + '%',))



                    curDest.execute("update crawl  "
                                    " set LandingPageUrl = replace(LandingPageUrl,?,  ?)"
                                    " where LandingPageUrl like ? ", (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update crawl  "
                                    " set WelcomePageUrl = replace(WelcomePageUrl,?,  ?)"
                                    " where WelcomePageUrl like ? ", (value,decodedvalue, '%' + value + '%',))



                    curDest.execute("update http_referrer_querystring  "
                                    " set url = replace(url,?,  ?)"
                                    " where url like ? ", (value,decodedvalue, '%' + value + '%',))



                    curDest.execute("update http_requests_pid  "
                                    " set url = replace(url,?,  ?)"
                                    " where url like ? ", (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update http_responses_querystring  "
                                    " set url = replace(url,?,  ?)"
                                    " where url like ? ", (value,decodedvalue, '%' + value + '%',))


                    curDest.execute("update http_requests_querystring  "
                                    " set url = replace(url,?,  ?)"
                                    " where url like ? ", (value,decodedvalue, '%' + value + '%',))


                    curDest.execute("update http_referrer_querystring  "
                                    " set decodedvalue = replace(decodedvalue,?,  ?)"
                                    " where decodedvalue like ? ", (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update http_requests_querystring  "
                                    " set decodedvalue = replace(decodedvalue,?,  ?)"
                                    " where decodedvalue like ? ", (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update http_responses_querystring  "
                                    " set decodedvalue = replace(decodedvalue,?,  ?)"
                                    " where decodedvalue like ? ", (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update http_profile_cookies  "
                                    " set decodedvalue = replace(decodedvalue,?,  ?)"
                                    " where decodedvalue like ? ", (value,decodedvalue, '%' + value + '%',))

                    curDest.execute("update http_localstorages  "
                                    " set decodedvalue = replace(decodedvalue,?,  ?)"
                                    " where decodedvalue like ? ", (value,decodedvalue, '%' + value + '%',))


                    cnnDestination.commit()

                    
#-------------------------
# populateIps
#-------------------------
def populateIps(ipAddress):            
    import json

    curDest.execute(" insert into list_ips (ip)"
                    "select distinct ip_dst"
                    " from http_requests"
                    " where not exists (select 'x' from list_ips x where x.ip = http_requests.ip_dst ) "
                    )#" and crawl_id=" +hotspot_params["crawl_id"])

    curDest.execute("  insert into list_ips (ip)"
                    " select distinct ip_src"
                    " from http_responses"
                    " where not exists (select 'x' from list_ips x where x.ip = http_responses.ip_src )"
                    )# " and crawl_id=" +hotspot_params["crawl_id"])

    
    if ipAddress == None:
        curDest.execute("select distinct ip from list_ips where type is null   limit 990")
    else:
        curDest.execute("select distinct ip from list_ips where type is null and ip='" + ipAddress + "'")

    rows = curDest.fetchall()
    url = "http://free.ipwhois.io/json/"

    for row in rows:
        try:
            IP = row[0]
            response = requests.post(url + IP)
            rp = response.json()
     

            if rp["continent"] == None:
                continent = ''
            else:
                continent = rp["continent"] 
            if rp["country"] == None:
                country = ''
            else:
                country = rp["country"] 
            if rp["type"] == None:
                type = ''
            else:
                type = rp["type"] 
            if rp["city"] == None:
                city = ''
            else:
                city = rp["city"]
            city = city.replace("'","''")    
            if rp["latitude"] == None:
                latitude = ''
            else:
                latitude = rp["latitude"] 
            if rp["longitude"] == None:
                longitude = ''
            else:
                longitude = rp["longitude"]
            asn = ''
            if "asn" in rp:    
                if rp["asn"] == None:
                    asn = ''
                else:
                    asn = rp["asn"]
                    
            if rp["org"] == None:
                org = ''
            else:
                org = rp["org"] 
            if rp["isp"] == None:
                isp = ''
            else:
                isp = rp["isp"] 
            curDest.execute( "update list_ips "
                             " set type='"+ type +"' "
                              ", continent = '" + continent + "' "
                              ", country = '" + country + "' "
                              ", country_code = '" + rp["country_code"] + "' "
                              ", city = '" + city + "' "
                              ", latitude = '" + latitude + "'  "
                              ", longitude = '" + longitude + "'"
                              ", asn = '" + asn + "' "
                              ", org = '" + org + "' "
                              ", isp = '" + isp + "' "
                              " where ip = '" + IP+ "'")
            cnnDestination.commit()

        except:
            print ("error ip")
            print (IP)




        #delete redundant ips
        curDest.execute("  delete from list_ips"
                                    " where rowid not in (select min(x.rowid)"
                                    " from list_ips x"
                                    " group by x.ip)"
                                    " and list_ips.country is null")
def right(s, amount):
    return s[-amount:]


#-----------------------
#updateownedby
#-----------------------
def updateownedby():
    curDest.execute("select distinct mainhost from list_domains where ownedby is null and ocsp=0  and mainhost is not null order by mainhost desc") #and mainhost in ('adnxs.com')")
    rows = curDest.fetchall()

    for row in rows:

        maindomain = row[0]
        #check if it is a valid IP
        try:
            #IP(maindomain)
            socket.inet_aton(maindomain)
            valid_ip = True
            curDest.execute(" insert into list_ips (ip)"
                            " select distinct mainHost"
                            " from list_domains"
                            " where not exists (select 'x' from list_ips x where x.ip = list_domains.mainHost ) "
                            " and mainHost = '" + maindomain + "'")
                            
            populateIps(maindomain)

  
        # legal
        except socket.error:
            # Not valid IP, search in whois database
            valid_ip = False
            
            try:
                w= whois.whois(maindomain)
                org = None
                source = ""
                if "org" in w:
                    if w.org != None:
                        if "REDACTED" not in w.org:
                            if "Not Disclosed" not in w.org:
                                if "Domains By Proxy, LLC" not in w.org:
                                    if "Domain Protection Services, Inc." not in w.org:
                                        if "WhoisGuard, Inc." not in w.org:
                                            if "Whois Privacy (enumDNS dba)" not in w.org:
                                                if "Whois Data Protection Sp. z o.o." not in w.org:
                                                        if "Privacy protection service - whoisproxy.ru" not in w.org:
                                                            if "Whois Privacy Service" not in w.org:
                                                                if "PrivateWHOIS" not in w.org:
                                                                    if "Privacy" not in w.org:
                                                                        if "Protection" not in w.org:
                                                                            if "Not Disclosed" not in w.org:
                                                                                org = w.org
                                                                                org = org.replace("'", "")

                                                                                source = "Org"

                                    
                if org == None:
                    if "registrant_name" in w:
                        if type(w.registrant_name) is  list:
                            org1 = w.registrant_name
                            if "REDACTED" not in org1:
                                if "Not Disclosed" not in org1:
                                        if "Domains By Proxy, LLC" not in org1:
                                            if "Domain Protection Services, Inc." not in org1:
                                                if "WhoisGuard, Inc." not in org1:
                                                    if "Whois Privacy (enumDNS dba)" not in org1:
                                                        if "Whois Data Protection Sp. z o.o." not in org1:
                                                            if "Privacy protection service - whoisproxy.ru" not in org1:
                                                                if "Whois Privacy Service" not in org1:
                                                                    if "PrivateWHOIS" not in org1:

                                                                        if "Privacy" not in org1:
                                                                            if "Protection" not in org1:
                                                                                if "Not Disclosed" not in org1:
                                                                                    org = org1[1]
                                                                                    org = org.replace("'", "")
                                                                                    source = "Registrant Name"
                        else:
                              if "REDACTED" not in w.registrant_name:
                                        if "Not Disclosed" not in w.registrant_name:
                                            if "Domains By Proxy, LLC" not in w.registrant_name:
                                                if "Domain Protection Services, Inc." not in w.registrant_name:
                                                    if "WhoisGuard, Inc." not in w.registrant_name:
                                                        if "Whois Privacy (enumDNS dba)" not in w.registrant_name:
                                                            if "Whois Data Protection Sp. z o.o." not in w.registrant_name:
                                                                if "Privacy protection service - whoisproxy.ru" not in w.registrant_name:
                                                                       if "Whois Privacy Service" not in w.registrant_name:
                                                                             if "Privacy" not in w.registrant_name:
                                                                                        if "Protection" not in w.registrant_name:
                                                                                            if "Not Disclosed" not in w.registrant_name:
                                                                                                if "PrivateWHOIS" not in w.registrant_name:
                                                                                                    org = w.registrant_name
                                                                                                    org = org.replace("'", "")
                                                                                                    source = "Registrant Name"

                #todo check whois https://website.informer.com/akstat.io#tab_stats

                #todo how did i get the details for pbbl.co while it is private
                email = ""
                emails = ""
                if "emails" in w:
                    if type(w.emails) is  list:

                            emails = w.emails
                            if emails!= None:
                                for e1 in emails:

                                    e=e1.replace(",","")
                                    if "REDACTED" not in e:
                                        if "abuse" not in e:
                                            if "a,b,u,s,e" not in e:
                                                if "whoisrequest" not in e:
                                                    if "whoisproxy" not in e:
                                                        if "whoisdataprotection" not in e:
                                                            if "networksolutionsprivateregistration" not in e:
                                                                if "proxyregistrant" not in e:
                                                                    if "whoisprivacyservice" not in e:
                                                                        if "registrar@amazon.com" not in e:
                                                                            if ",admin@internationaladmin.com" not in e:
                                                                                if "cscglobal.com" not in e:
                                                                                    if "superprivacyservice.com" not in e:
                                                                                        if "superprivacyservice.com" not in e:
                                                                                            if "contactprivacy.com" not in e:
                                                                                                if "whoisguard.com" not in e:
                                                                                                    if "whoisprivacy.com" not in e:
                                                                                                        if "wnamesproprivacy.ca" not in e:
                                                                                                            if "anonymised.email" not in e:
                                                                                                                if "dataprivacyprotected@1und1.de" not in e:
                                                                                                                    if "domainprivacygroup.com" not in e:
                                                                                                                        if "contactprivacy.com" not in e:
                                                                                                                            if "domainsbyproxy.com" not in e:
                                                                                                                                if "contact.gandi.net" not in e:
                                                                                                                                    if "domainbox.com" not in e:
                                                                                                                                        if email =="" :
                                                                                                                                            email = e
                                                                                                                                        else:    
                                                                                                                                            email = email + "," +  e 
                                                

                name_server = ""
                name_servers = ""
                if "name_servers" in w:
                        name_servers = w.name_servers
                        if name_servers!= None:
                            for e in name_servers:
                                if name_server =="" :
                                    name_server = e
                                else:    
                                    name_server = name_server + "," +  e 
                
                dnssec = ""
                if "dnssec" in w:
                    if w.dnssec != None:
                        if "REDACTED" not in w.dnssec:
                            if "Not Disclosed" not in w.dnssec:
                                dnssec = w.dnssec
                                if type(dnssec) is list:
                                    dnssec = ''.join(str(e) for e in dnssec)
                admin_name = ""
                if "name" in w:
                    if w.name != None:
                        if "REDACTED" not in w.name:
                            if "Not Disclosed" not in w.name:
                                name = w.name

                address = ""
                if "address" in w:
                    if w.address != None:
                        if "REDACTED" not in w.address:
                            if "Not Disclosed" not in w.address:
                                address = w.address
                                if type(address) is  not list:
                                
                                    address = address.replace("'", "")
                                else:
                                    address = address[1]
                city = ""
                if "city" in w:
                    if w.city != None:
                        if "REDACTED" not in w.city:
                            if "Not Disclosed" not in w.city:
                                city = w.city
                        
                state = ""
                if "state" in w:
                    if w.state != None:
                        if "REDACTED" not in w.state:
                            if "Not Disclosed" not in w.state:
                                state = w.state
                zipcode = ""
                if "zipcode" in w:
                    if w.zipcode != None:
                        if "REDACTED" not in w.zipcode:
                            if "Not Disclosed" not in w.zipcode:
                                zipcode = w.zipcode
                country = ""
                if "country" in w:
                    if w.country != None:
                        if "REDACTED" not in w.country:
                            if "Not Disclosed" not in w.country:
                                country = w.country
     


                if org != None:
                    curDest.execute( "update list_domains set ownedby = '" + org + "', source ='" +source + "'"
                             " where mainhost = '" + maindomain+ "'")


                curDest.execute( "update list_domains set name_servers = '" +name_server + "',emails = '" + email + "', dnssec ='" +dnssec + "', admin_name = '" + admin_name + "',address= '" +address +"',city='" + city + "',state='" + state + "',zipcode='"+zipcode + "',country='" +country + "'" 
                             " where mainhost = '" + maindomain+ "'")
                    
            
            except Exception as e:
                print (e)
                print ("error domain")
                print (maindomain)

        


            curDest.execute(" update list_domains"
                          " set ocsp = 1"
                          " where host like 'ocsp?.%' or  host like 'crl?.%' or  host like 'pki?.%'"
                          " or mainhost in (select distinct x.mainhost from list_domains x where x.ocsp = 1)")

#--------------------------
# uploadchrome_level
#--------------------------
def uploadchrome_level():
    file= os.path.join(directory_path,'levelcookie.txt')
    if  os.path.isfile(file):
 
        with open(file,"r") as f:
            for line in f: #todo check why it does not always works
                    #print (line)
                #try:
                    for kv in line.split('!!!'):
                        kv1 = kv.strip()
                        kv1 = kv1.replace(u'\\"', '"')
                        kv1 = kv1.replace(u'\\\\"', '')
                        kv1 = kv1.replace(u'"}"', '"}')
                        if right(kv1,1) == '"':
                           kv1 = kv1[:-1] 
                        
                        #print (kv1)
                        if kv1 != '"undefined' and kv1.strip() != 'undefined' :
                            cookie = json.loads(kv1)
                            #print (cookie)
                            curDest.execute("select crawl_id, name,basedomain from http_profile_cookies where crawl_id=? and name=? and host=?", (hotspot_params["crawl_id"],cookie["name"],cookie["domain"]))
                            data = curDest.fetchone()

                            if cookie["session"]:
                              expiry = 0
                            else:
                              expiry = cookie["expirationDate"] 


                            domain=  cookie["domain"]
                            domain = "http://" + domain + "/"
                            
                            list1 = tldextract.extract(domain)
                            
                            if list1.suffix != '':
                                domain_name = list1.domain + '.' + list1.suffix
                            else:
                                domain_name = list1.domain
                    
                          
                            if data == None:
                                query = "INSERT INTO http_profile_cookies ( crawl_id,name,value,baseDomain,hostOnly,path,isSecure,ishttponly,expiry,sameSite,host,source,creationTime) VALUES "\
                                         "(?,?,?,?,?,?,?,?,?,?,?,?,?)"
                                curDest.execute(query,(hotspot_params["crawl_id"], cookie["name"], cookie["value"], domain_name, cookie["hostOnly"], cookie["path"], cookie["secure"], cookie["httpOnly"], expiry,cookie["sameSite"],cookie["domain"],'js',cookie["createdate"]))
                         
                    

                #except Exception as e:
                #    continue
                    
        f.close()
        
#------------------------------
# copyleveldb
#-----------------------------                   
def copyleveldb(myfile,db_name):

    ## If file exists, delete it ##
    if os.path.isdir(myfile):
        shutil.rmtree(myfile)
    #copy file to destination folder
    try:
        
            from_path = os.path.join(directory_path, 'Browser_Profile','Local Extension Settings',db_name)
            to_path = os.path.join(os.path.dirname(__file__), 'level')
            if os.path.isdir(from_path):
                    shutil.copytree(from_path,myfile   ,ignore=shutil.ignore_patterns("parent.lock", "lock", ".parentlock"))
                
    except:
        print ("error importing level db")
        
#------------------------------
# dump_cookies
#-----------------------------
def dump_cookies( strpath):
    #delete cookie level db
    try:
        db_name= hotspot_params["hotspot_extension_version"]
    except:
        db_name='dhadoephijildiffikhbihhiddbbkkdo'

    print ("-----......................................")
    print (os.path.join(os.path.dirname(__file__), 'level',db_name))
    print ("----.....................................-")
        
    copyleveldb(os.path.join(os.path.dirname(__file__), 'level',db_name),db_name)
                        
    if os.path.isdir(os.path.join(os.path.dirname(__file__), 'level',db_name)):
        outname = os.path.join(strpath,'levelcookie.txt')
        os.chdir(os.path.join(os.path.dirname(__file__), 'level'))
        #sys.stdout = open(outname, 'w')
        if db_name == "dhadoephijildiffikhbihhiddbbkkdo":
            #todo check how to send parameter to the javascript file with dbname
            jsfile_path = os.path.join(os.path.dirname(__file__), 'level', "getcookie1.js")
        else:
            jsfile_path = os.path.join(os.path.dirname(__file__), 'level', "getcookie2.js")
                                  
        args  = ["node", jsfile_path, ">", outname]
        p = subprocess.Popen(args , bufsize=0, shell=True, executable="C:\\Windows\\System32\\cmd.exe")

        


class SingleRuleParser:

    BINARY_OPTIONS = [
        "script",
        "image",
        "stylesheet",
        "object",
        "xmlhttprequest",
        "object-subrequest",
        "subdocument",
        "document",
        "elemhide",
        "other",
        "background",
        "xbl",
        "ping",
        "dtd",
        "media",
        "third-party",
        "match-case",
        "collapse",
        "donottrack",
    ]
    OPTIONS_SPLIT_PAT = ',(?=~?(?:%s))' % ('|'.join(BINARY_OPTIONS + ["domain"]))
    OPTIONS_SPLIT_RE = re.compile(OPTIONS_SPLIT_PAT)

    def __init__(self, rule_text):
        self.raw_rule_text = rule_text
        self.regex_re = None

        rule_text = rule_text.strip()
        self.is_comment = rule_text.startswith(('!', '[Adblock'))
        if self.is_comment:
            self.is_html_rule = self.is_exception = False
        else:
            self.is_html_rule = '##' in rule_text or '#@#' in rule_text  # or rule_text.startswith('#')
            self.is_exception = rule_text.startswith('@@')
            if self.is_exception:
                rule_text = rule_text[2:]

        if not self.is_comment and '$' in rule_text:
            rule_text, options_text = rule_text.split('$', 1)
            self.raw_options = self._split_options(options_text)
            self.options = dict(self._parse_option(opt) for opt in self.raw_options)
        else:
            self.raw_options = []
            self.options = {}
        self._options_keys = frozenset(self.options.keys()) - set(['match-case'])

        self.rule_text = rule_text

        if self.is_comment or self.is_html_rule:
            # TODO: add support for HTML rules.
            # We should split the rule into URL and HTML parts,
            # convert URL part to a regex and parse the HTML part.
            self.regex = ''
        elif not rule_text:
            self.is_comment = True
            self.regex = ''
        else:
            self.regex = self.rule_to_regex(rule_text)

    def match_url(self, url, options=None):
        options = options or {}
        for optname in self.options:
            if optname == 'match-case':  # TODO
                continue

            if optname not in options:
                raise ValueError("Rule requires option %s" % optname)

            if optname == 'domain':
                if not self._domain_matches(options['domain']):
                    return False
                continue

            if options[optname] != self.options[optname]:
                return False

        return self._url_matches(url)

    def _domain_matches(self, domain):
        domain_rules = self.options['domain']
        for domain in _domain_variants(domain):
            if domain in domain_rules:
                return domain_rules[domain]
        return not any(domain_rules.values())

    def _url_matches(self, url):
        if self.regex_re is None:
            self.regex_re = re.compile(self.regex)
        return bool(self.regex_re.search(url))

    def matching_supported(self, options=None):
        if self.is_comment:
            return False

        if self.is_html_rule:  # HTML rules are not supported yet
            return False

        options = options or {}
        keys = set(options.keys())
        if not keys.issuperset(self._options_keys):
            # some of the required options are not given
            return False

        return True

    def get_html_rule(self):
        return self.is_html_rule

    def get_comment(self):
        return self.is_comment

    def get_keys(self):
        return self._options_keys

    @classmethod
    def _split_options(cls, options_text):
        return cls.OPTIONS_SPLIT_RE.split(options_text)

    @classmethod
    def _parse_domain_option(cls, text):
        domains = text[len('domain='):]
        parts = domains.replace(',', '|').split('|')
        return dict(cls._parse_option_negation(p) for p in parts)

    @classmethod
    def _parse_option_negation(cls, text):
        return (text.lstrip('~'), not text.startswith('~'))

    @classmethod
    def _parse_option(cls, text):
        if text.startswith("domain="):
            return ("domain", cls._parse_domain_option(text))
        return cls._parse_option_negation(text)

    @classmethod
    def rule_to_regex(cls, rule):
        if not rule:
            raise ValueError("Invalid rule")
            # return rule

        # escape special regex characters
        rule = re.sub(r"([.$+?{}()\[\]\\])", r"\\\1", rule)

        rule = rule.replace("^", "(?:[^\w\d_\-.%]|$)")
        rule = rule.replace("*", ".*")
        if rule[-1] == '|':
            rule = rule[:-1] + '$'

        if rule[:2] == '||':
            # XXX: it is better to use urlparse for such things,
            # but urlparse doesn't give us a single regex.
            # Regex is based on http://tools.ietf.org/html/rfc3986#appendix-B
            if len(rule) > 2:
                #          |            | complete part     |
                #          |  scheme    | of the domain     |
                rule = r"^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?" + rule[2:]

        elif rule[0] == '|':
            rule = '^' + rule[1:]

        rule = re.sub("(\|)[^$]", r"\|", rule)
        return rule

    def get_rule(self):
        return self.raw_rule_text

class Parser:

    def __init__(self, rules, rule_cls=SingleRuleParser):

        self.supported_options = rule_cls.BINARY_OPTIONS + ['domain']
        self.rule_cls = rule_cls
        self.rules = []
        for r in rules:
            self.rules.append(rule_cls(r))

        advanced_rules, basic_rules = split_data(self.rules, lambda r: r.options)

        # TODO: what about ~rules? Should we match them earlier?
        domain_required_rules, non_domain_rules = split_data(
            advanced_rules,
            lambda r: (
                'domain' in r.options
                and any(r.options["domain"].values())
            )
        )

        # split rules into blacklists and whitelists
        self.blacklist, self.whitelist = self._split_bw(basic_rules)
        self.blacklist_with_options, self.whitelist_with_options = self._split_bw(non_domain_rules)
        self.blacklist_require_domain, self.whitelist_require_domain = self._split_bw_domain(domain_required_rules)

    def check(self, url, options=None):
        options = options or {}
        if self.is_whitelisted(url, options):
            return 1
        if self.is_blacklisted(url, options):
            return -1
        return 0

    def check_with_items(self, url, options=None):
        options = options or {}
        if self.is_whitelisted(url, options):
            return 1, []
        blacklisted, items = self.is_blacklisted_with_items(url, options)
        if blacklisted:
            return -1, items
        return 0, []

    def is_whitelisted(self, url, options=None):
        return self._matches(url, options, self.whitelist, self.whitelist_require_domain, self.whitelist_with_options)

    def is_blacklisted(self, url, options=None):
        return self._matches(url, options, self.blacklist, self.blacklist_require_domain, self.blacklist_with_options)

    def is_blacklisted_with_items(self, url, options=None):
        return self._matches_with_items(url, options, self.blacklist, self.blacklist_require_domain, self.blacklist_with_options)

    def _matches(self, url, options, general_rules, domain_required_rules, rules_with_options):
        rules = general_rules + rules_with_options
        if options and 'domain' in options and domain_required_rules:
            src_domain = options['domain']
            for domain in _domain_variants(src_domain):
                if domain in domain_required_rules:
                    rules.extend(domain_required_rules[domain])
        rules = [rule for rule in rules if rule.matching_supported(options)]
        return any(rule.match_url(url, options) for rule in rules)

    def _matches_with_items(self, url, options, general_rules, domain_required_rules, rules_with_options):
        rules = general_rules + rules_with_options
        if options and 'domain' in options and domain_required_rules:
            src_domain = options['domain']
            for domain in _domain_variants(src_domain):
                if domain in domain_required_rules:
                    rules.extend(domain_required_rules[domain])
        rules = [rule for rule in rules if rule.matching_supported(options)]
        matches = False
        items = []
        for rule in rules:
            if rule.match_url(url, options):
                matches = True
                items.append(rule.get_rule())
        return matches, items

    @classmethod
    def _split_bw(cls, rules):
        return split_data(rules, lambda r: not r.is_exception)

    @classmethod
    def _split_bw_domain(cls, rules):
        blacklist, whitelist = cls._split_bw(rules)
        return cls._domain_index(blacklist), cls._domain_index(whitelist)

    @classmethod
    def _domain_index(cls, rules):
        result = defaultdict(list)
        for rule in rules:
            domains = rule.options.get('domain', {})
            for domain, required in domains.items():
                if required:
                    result[domain].append(rule)
        return dict(result)

    def print_rules(self):
        for rule in self.blacklist:
            print("1:", rule.get_rule())
        for rule in self.whitelist:
            print("2:",rule.get_rule())
        for domain in self.blacklist_require_domain:
            for rule in self.blacklist_require_domain[domain]:
                print("3:", domain, ":", rule.get_rule())
        for domain in self.whitelist_require_domain:
            for rule in self.whitelist_require_domain[domain]:
                print("4:", domain, ":", rule.get_rule())
        for rule in self.blacklist_with_options:
            print("5:", rule.get_rule())
        for rule in self.whitelist_with_options:
            print("6:", rule.get_rule())


def _domain_variants(domain):
    """
    >>> list(_domain_variants("foo.bar.example.com"))
    ['foo.bar.example.com', 'bar.example.com', 'example.com']
    >>> list(_domain_variants("example.com"))
    ['example.com']
    """
    parts = domain.split('.')
    for i in range(len(parts), 1, -1):
        yield ".".join(parts[-i:])


def split_data(iterable, pred):
    """
    Split data from ``iterable`` into two lists.
    Each element is passed to function ``pred``; elements
    for which ``pred`` returns True are put into ``yes`` list,
    other elements are put into ``no`` list.

    >>> split_data(["foo", "Bar", "Spam", "egg"], lambda t: t.istitle())
    (['Bar', 'Spam'], ['foo', 'egg'])
    """
    yes, no = [], []
    for d in iterable:
        if pred(d):
            yes.append(d)
        else:
            no.append(d)
    return yes, no


class FastHash:
    """A class to calculate fast hash for strings of a given constant length
    x_i = t_i*R^(M-1) + t_(i+1)*R^(M-2) + ... + t_(i+M-1)*R^0 (mod Q)"""

    def __init__(self, string_size):
        self.M = string_size
        self.R = 256
        self.Q = 179424673  # big prime number
        self.multipliers = []
        for i in reversed(range(self.M)):
            self.multipliers.append((self.R**i)%self.Q)

    def compute_hash(self, s, start_index = 0):
        if (len(s) - start_index) < self.M:
            print("String length not equal to required length of %d" % self.M)
            return -1
        hash_value = 0
        for i in range(self.M):
            hash_value = (hash_value + (ord(s[i+start_index])*self.multipliers[i])%self.Q)%self.Q
        return hash_value

    def extend_hash(self, s, start_index=0, prev_hash=-1):
        if start_index == 0:
            return self.compute_hash(s, start_index)
        if (len(s) - start_index) < self.M:
            print("String length not equal to required length of %d" % self.M)
            return -1
        hash_value = ((prev_hash - ord(s[start_index-1])*self.multipliers[0])*self.R + ord(s[start_index + self.M - 1]))%self.Q
        return hash_value

class BlockListParser:
    """Creates maps of shortcut hashes with regex of the urls"""

    def __init__(self, regex_file=None, regexes=None, shortcut_sizes=None, print_maps=False, support_hash=False):
        """Initializes the shortcut to Parser map"""
        if regex_file is None:
            regex_lines = regexes
        else:
            with open(regex_file,encoding = 'utf-8') as f:
                regex_lines = f.readlines()
        self.regex_lines = regex_lines
        self.fast_hashes = []
        self.print_maps = print_maps
        self.support_hash = support_hash
        if shortcut_sizes:
            self.shortcut_sizes = shortcut_sizes
        else:
            self.shortcut_sizes = self._determine_shortcut_sizes(len(regex_lines))
        for shortcut_size in self.shortcut_sizes:
            self.fast_hashes.append(FastHash(shortcut_size))
        all_shortcut_url_maps, remaining_lines = self._get_all_shortcut_url_maps(regex_lines)
        self.all_shortcut_parser_maps = self._get_all_shortcut_parser_maps(all_shortcut_url_maps)
        self.remaining_regex = self._convert_to_regex(remaining_lines)

    def get_num_classes(self):
        # always supports only binary classification, blocked or not blocked
        return 2

    def get_classes_description(self):
        return ['Not Blocked', 'Blocked']

    def should_block(self, url, options=None):
        """Check if url is in the patterns"""
        if self.support_hash:
            return self._should_block_with_hash()
        blacklisted = False
        for k in range(len(self.shortcut_sizes)):
            shortcut_size = self.shortcut_sizes[k]
            regex_map = self.all_shortcut_parser_maps[k]
            for i in range(len(url) - shortcut_size + 1):
                cur_sub = url[i:i+shortcut_size]
                if cur_sub in regex_map:
                    parser = regex_map[cur_sub]
                    if blacklisted:
                        if parser.is_whitelisted(url, options):
                            return False
                    else:
                        state = parser.check(url, options)
                        if state == 1:
                            return False
                        elif state == -1:
                            blacklisted = True
        if blacklisted:
            if self.remaining_regex.is_whitelisted(url, options):
                return False
        else:
            state = self.remaining_regex.check(url, options)
            if state == 1:
                return False
            elif state == -1:
                blacklisted = True
        return blacklisted

    def should_block_and_print(self, url, options=None):
        """Check if url is in the patterns"""
        if self.support_hash:
            return self._should_block_with_hash()
        blacklisted = False
        for k in range(len(self.shortcut_sizes)):
            shortcut_size = self.shortcut_sizes[k]
            regex_map = self.all_shortcut_parser_maps[k]
            for i in range(len(url) - shortcut_size + 1):
                cur_sub = url[i:i+shortcut_size]
                if cur_sub in regex_map:
                    parser = regex_map[cur_sub]
                    if blacklisted:
                        if parser.is_whitelisted(url, options):
                            print("Whitelisted by---------")
                            parser.print_rules()
                            return False
                    else:
                        state = parser.check(url, options)
                        if state == 1:
                            print("Whitelisted by---------")
                            parser.print_rules()
                            return False
                        elif state == -1:
                            print("Blacklisted by---------")
                            parser.print_rules()
                            blacklisted = True
        if blacklisted:
            if self.remaining_regex.is_whitelisted(url, options):
                print("Whitelisted by---------")
                parser.print_rules()
                return False
        else:
            state = self.remaining_regex.check(url, options)
            if state == 1:
                print("Whitelisted by---------")
                parser.print_rules()
                return False
            elif state == -1:
                print("Blacklisted by---------")
                parser.print_rules()
                blacklisted = True
        return blacklisted

    def should_block_with_items(self, url, options=None):
        blacklisting_items = []
        blacklisted = False
        for k in range(len(self.shortcut_sizes)):
            shortcut_size = self.shortcut_sizes[k]
            regex_map = self.all_shortcut_parser_maps[k]
            for i in range(len(url) - shortcut_size + 1):
                cur_sub = url[i:i+shortcut_size]
                if cur_sub in regex_map:
                    parser = regex_map[cur_sub]
                    state, items = parser.check_with_items(url, options)
                    if state == 1:
                        return False, []
                    elif state == -1:
                        blacklisting_items += items
                        blacklisted = True
        state, items = self.remaining_regex.check_with_items(url, options)
        if state == 1:
            return False, []
        elif state == -1:
            blacklisting_items += items
            blacklisted = True
        return blacklisted, blacklisting_items

    def get_block_class(self, url, options=None):
        if self.should_block(url, options):
            return 1
        else:
            return 0

    def get_block_class_with_items(self, url, options=None):
        block, items = self.should_block_with_items(url, options)
        if block:
            return 1, items
        else:
            return 0, items

    @staticmethod
    def get_all_items(regex_file):
        with open(regex_file) as f:
            regex_lines = f.readlines()
        return regex_lines

    def _determine_shortcut_sizes(self, num_regex_lines):
        """Empirically the following returns the best value"""
        return [14, 10, 6, 4]

    def _convert_to_regex(self, lines):
        return Parser(lines)

    def _should_block_with_hash(self, url, options):
        blacklisted = False
        for k in range(len(self.shortcut_sizes)):
            fast_hash = self.fast_hashes[k]
            shortcut_size = self.shortcut_sizes[k]
            regex_map = self.all_shortcut_parser_maps[k]
            prev_hash = -1
            for i in range(len(url) - shortcut_size + 1):
                cur_hash = fast_hash.extend_hash(url, i, prev_hash)
                if cur_hash in regex_map:
                    parser = regex_map[cur_hash]
                    if blacklisted:
                        if parser.is_whitelisted(url, options):
                            return False
                    else:
                        state = parser.check(url, options)
                        if state == 1:
                            return False
                        elif state == -1:
                            blacklisted = True
                prev_hash = cur_hash
        if blacklisted:
            if self.remaining_regex.is_whitelisted(url, options):
                return False
        else:
            state = self.remaining_regex.check(url, options)
            if state == 1:
                return False
            elif state == -1:
                blacklisted = True
        return blacklisted

    def _print_num_map(self, shortcut_url_map):
        num_shortcuts = {}
        num_shortcuts_stored = {}
        for shortcut in shortcut_url_map:
            num = len(shortcut_url_map[shortcut])
            if num in num_shortcuts:
                num_shortcuts[num] += 1
                num_shortcuts_stored[num].append(shortcut)
            else:
                num_shortcuts[num] = 1
                num_shortcuts_stored[num] = [shortcut]
        print(num_shortcuts)

    def _print_statistics_of_map(self, shortcut_size, total_rules, total_comments,
                                 total_shortcuts, total_secondary_lines, shortcut_url_map):
        print("**********     Shortcut size is %d     **********" % shortcut_size)
        print("Number of rules = ", total_rules, ", comments = ", total_comments)
        print("Shortcuts found for ", total_shortcuts, " rules")
        print("Shortcuts not found for ", total_secondary_lines, " rules")
        print("Number map is")
        self._print_num_map(shortcut_url_map)
        print("")

    def _get_shortcut_url_map(self, pat, lines, shortcut_size):
        shortcut_url_map = {}
        secondary_lines = []
        total_rules = 0
        total_comments = 0
        total_shortcuts = 0
        for line in lines:
            line.strip()
            if line[0] == '!':
                total_comments += 1
                continue
            total_rules += 1
            url = re.split(r'\$+', line)[0]
            searches = pat.findall(url)
            flag = 0
            if searches:
                total_shortcuts += 1
            else:
                secondary_lines.append(line)
                continue
            min_count = -1
            for s in searches:
                for i in range(len(s) - shortcut_size+1):
                    cur_s = s[i:i+shortcut_size]
                    if cur_s not in shortcut_url_map:
                        shortcut_url_map[cur_s] = [line]
                        flag = 1
                        break
                    if min_count == -1 or len(shortcut_url_map[cur_s]) < min_count:
                        min_count = len(shortcut_url_map[cur_s])
                        min_s = cur_s
                if flag == 1:
                    break
            if flag == 0:
                shortcut_url_map[min_s].append(line)
        if self.print_maps:
            self._print_statistics_of_map(shortcut_size, total_rules, total_comments,
                                          total_shortcuts, len(secondary_lines), shortcut_url_map)
        return shortcut_url_map, secondary_lines

    def _get_all_shortcut_url_maps(self, lines):
        all_shortcut_url_maps = []
        for shortcut_size in self.shortcut_sizes:
            pat = re.compile(r'[\w\/\=\.\-\?\;\,\&]{%d,}' % shortcut_size)
            shortcut_url_map, lines = self._get_shortcut_url_map(pat, lines, shortcut_size)
            all_shortcut_url_maps.append(shortcut_url_map)
        return all_shortcut_url_maps, lines

    def _get_shortcut_parser_map(self, fast_hash, shortcut_url_map):
        shortcut_parser_map = {}
        if self.support_hash:
            for shortcut in shortcut_url_map:
                hash_value = fast_hash.compute_hash(shortcut)
                if hash_value in shortcut_parser_map:
                    shortcut_parser_map[hash_value].append(shortcut_url_map[shortcut])
                else:
                    shortcut_parser_map[hash_value] = shortcut_url_map[shortcut]
            for hash_key in shortcut_parser_map:
                shortcut_parser_map[hash_key] = self._convert_to_regex(shortcut_parser_map[hash_key])
        else:
            for shortcut in shortcut_url_map:
                shortcut_parser_map[shortcut] = self._convert_to_regex(shortcut_url_map[shortcut])
        return shortcut_parser_map

    def _get_all_shortcut_parser_maps(self, all_shortcut_url_maps):
        all_shortcut_parser_maps = []
        for fast_hash, shortcut_url_map in zip(self.fast_hashes, all_shortcut_url_maps):
            all_shortcut_parser_maps.append(self._get_shortcut_parser_map(fast_hash, shortcut_url_map))
        return all_shortcut_parser_maps

"""
This file contains a collection of utilities for working with BlockListParser
using http data, such as that collected by OpenWPM (https://github.com/citp/OpenWPM).

publicsuffix (https://pypi.python.org/pypi/publicsuffix/) is required

Example usage:

    from publicsuffix import PublicSuffixList
    from BlockListParser import BlockListParser

    psl = PublicSuffixList()
    easylist = BlockListParser('easylist.txt')

    # Sample data
    url = 'http://www.advertiser.com/ads/ad.js'
    top_url = 'http://www.example.com'
    content_type = 'application/javascript'

    options = get_option_dict(url, top_url,
                is_js(url, content_type),
                is_image(url, content_type),
                psl)
    if easylist.should_block(url, options):
        print "URL %s would have been blocked by easylist" % url

"""
# Manual mapping created by examining the content types of responses on the
# top 1 million homepages in March 2016
content_type_map = {
    'script': lambda x: (
        'javascript' in x
        or 'ecmascript' in x
        or x.endswith('text/js')
    ),
    'image': lambda x: (
        'image' in x
        or 'img' in x
        or 'jpg' in x
        or 'jpeg' in x
        or 'gif' in x
        or 'png' in x
        or 'ico' in x
    ),
    'video': lambda x: (
        ('video' in x
        or 'movie' in x
        or 'mp4' in x
        or 'webm' in x)
        and 'flv' not in x
    ),
    'css': lambda x: 'css' in x,
    'html': lambda x: 'html' in x,
    'plain': lambda x: 'plain' in x and 'html' not in x,
    'font': lambda x: 'font' in x or 'woff' in x,
    'json': lambda x: 'json' in x,
    'xml': lambda x: 'xml' in x and 'image' not in x,
    'flash': lambda x: 'flash' in x or 'flv' in x or 'swf' in x,
    'audio': lambda x: 'audio' in x,
    'stream': lambda x: 'octet-stream' in x,
    'form': lambda x: 'form' in x,
    'binary': lambda x: 'binary' in x and 'image' not in x
}

IMAGE_TYPES = {'tif', 'tiff', 'gif', 'jpeg',
               'jpg', 'jif', 'jfif', 'jp2',
               'jpx', 'j2k', 'j2c', 'fpx',
               'pcd', 'png'}

def get_top_level_type(content_type):
    """Returns a "top level" type for a given mimetype string.

    This uses a manually compiled mapping of mime types. The top level types
    returned are approximately mapped to request context types in Firefox

    Parameters
    ----------
    content_type : str
        content type string from the http response.

    Returns
    -------
    str
        "top level" content type, e.g. 'image' or 'script'
    """
    #print (content_type)
    if ';' in content_type:
        content_type = content_type.split(';')[0]
    for k,v in content_type_map.items():
        if v(content_type.lower()):
            return k
    return None

def is_passive(content_type):
    """Checks if content is likely considered passive content.

    Note that browsers block on *request* context, not response. For example,
    the request generated from a <script> element will be classified as active
    content. A custom mapping of response content types is used to determine
    the likely classification, but this will be imperfect. Passive content as
    defined here (ignoring <object> subresources):
        https://developer.mozilla.org/en-US/docs/Security/Mixed_content

    Parameters
    ----------
    content_type : str
        content type string from the http response.

    Returns
    -------
    bool
        True if the content_type indicates passive content, false otherwise.
    """
    return get_top_level_type(content_type) in ['image','audio','video']

def is_active(content_type):
    """Checks if content is likely considered active content.

    Note that browsers block on *request* context, not response. For example,
    the request generated from a <script> element will be classified as active
    content. A custom mapping of response content types is used to determine
    the likely classification, but this will be imperfect.

    Parameters
    ----------
    content_type : str
        content type string from the http response.

    Returns
    -------
    bool
        True if the content_type indicates active content, false otherwise.
    """
    return not is_passive(content_type)

def is_img(url, content_type):
    """Determine if a request url is an image.

    Preference is given to the content type, but will fall back to the
    extension of the url if necessary.

    Parameters
    ----------
    url : str
        request url
    content_type : str
        content type header of the http response to the request

    Returns
    -------
    bool
        True if the request is an image, false otherwise.
    """
    if get_top_level_type(content_type) == 'image':
        return True
    extension = urlparse(url).path.split('.')[-1]
    if extension.lower() in IMAGE_TYPES:
        return True
    return False

def is_js(url, content_type):
    """Determine if a request url is javascript.

    Preference is given to the content type, but will fall back to the
    extension of the url if necessary.

    Parameters
    ----------
    url : str
        request url
    content_type : str
        content type header of the http response to the request

    Returns
    -------
    bool
        True if the request is a JS file, false otherwise.
    """
    if get_top_level_type(content_type) == 'script':
        return True
    if urlparse(url).path.split('.')[-1].lower() == 'js':
        return True
    return False

def get_option_dict(url, top_url, url_owner,top_url_owner, is_js, is_image, public_suffix_list):
    """Build an options dict for BlockListParser

    Parameters
    ----------
    url : str
        request url to be checked by BlockListParser
    top_url : str
        url of the top-level page the request is occuring on
    is_js : bool
        indicates if this request is js
    is_image : bool
        indicates if this request is an image
    public_suffix_list : PublicSuffixList
        An instance of PublicSuffixList()

    Returns
    -------
    dict
        An "options" dictionary for use with BlockListParser
    """
    options = {}
    options["image"] = is_image
    options["script"] = is_js
    options["third-party"] = False
    options["domain"] = ""
    options["top_url"] = top_url


 
    top_hostname = urlparse(top_url).hostname
    hostname = urlparse(url).hostname

    top_domain = public_suffix_list.get_public_suffix(top_hostname)


    if hostname != None:
        domain = public_suffix_list.get_public_suffix(hostname)
   
    if params["Thirdparty"] !='website':
       
        if not top_domain == domain:

            options["third-party"] = True
    else:
       if not url_owner == top_url_owner:            
           options["third-party"] = True
    options["domain"] = top_hostname
    return options
   





#------------------------------
# Generate CSV files by calling powershell command
#-----------------------------
def GenerateCsvFiles(PS_File, Hotspot_Path):
 powerShellPath = r'/usr/bin/pwsh'
 powerShellCmd = PS_File
 
 p = subprocess.Popen([powerShellPath, '-ExecutionPolicy', 'Bypass', '-NonInteractive ', '-file', powerShellCmd, Hotspot_Path]
 , stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 output, error = p.communicate()
 rc = p.returncode

 print (error)
 print (rc)



#------------------------------
# Reverse String
#-----------------------------
def reverse_a_string(a_string):
    new_string = ''
    index = len(a_string)
    while index:
        index -= 1                    # index = index - 1
        new_string += a_string[index] # new_string = new_string + character
    new_string= new_string.replace("sptth:","")
    new_string= new_string.replace("ptth:","")
    new_string= new_string.replace("344:","")
    new_string= new_string.replace("08:","")
    
    return new_string


#------------------------------
# Parse cookies 
#-----------------------------
def parse_dict_cookies(value):
    result = {}
    
    for item in value.split(';'):
        item = item.strip()
        if not item:
            continue
        if '=' not in item:
            result[item] = None
            continue
            
        name, value = item.split('=', 1)
        result[name] = value
    return result

#------------------------------
# Load defualt application parameter
#-----------------------------
def load_default_params():
   
    fp = open(os.path.join(os.path.dirname(__file__),
                           'paramsparentalcontrol.json'))
    params = json.load(fp)
    fp.close()

    return params

#------------------------------
# Load defualt hotspot parameter
#-----------------------------
def load_hostspot_default_params(hostspot_path):

    try:
    
        fp = open(os.path.join(hostspot_path,
                               'params.json'))
        hotspot_params = json.load(fp)
        fp.close()
    except:
        fp = open(os.path.join(hostspot_path,
                               'temp_params.json'))
        hotspot_params = json.load(fp)
        fp.close()

    if "Mobile" in hotspot_params:
            if hotspot_params["Mobile"] ==None:
                hotspot_params["Mobile"]= "No"
    else:
            hotspot_params["Mobile"]= "No"
    
    return hotspot_params

#------------------------------
# Prepare cookie string
#-----------------------------
def preparecookiestring(value):
    result = value.replace("Sat", "")
    result = result.replace("Set-Cookie: ","")
    result = result.replace("Sun", "")
    result = result.replace("Mon", "")
    result = result.replace("Tue", "")
    result = result.replace("Wed", "")
    result = result.replace("Thu", "")
    result = result.replace("Fri", "")
    result = result.replace("expires=, ", "expires=")
    result = result.replace("Expires=, ", "expires=")

    return result

#------------------------------
# datetime_from_gmt_to_local
#-----------------------------   
def datetime_from_gmt_to_local(local_datetime):
    from_zone = tz.gettz('GMT')
    to_zone = tz.tzlocal()
    now_timestamp = time.time()
    offset = datetime.gmtfromtimestamp(now_timestamp) - datetime.fromtimestamp(now_timestamp)
    return local_datetime - offset



#------------------------------
# update_DFPM_Thirdparty
#-----------------------------
def update_DFPM_Thirdparty(iscativeportal):

    try:

        if params["Thirdparty"] == 'website':

            if iscativeportal == 1:
                    curDest.execute("select distinct x.id, x.url,x.method,x.symbol,x.host,x.level,x.category,x.function_name,x.script_url,x.script_line,x.script_col,ifnull(crawl.welcome_page_domain,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.welcome_page_domain) top_url_owner "
                            " from DFPM_javascript x"
                            " inner join crawl on crawl.crawl_id = x.crawl_id"
                            " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                            " where x.active = 1 "
                            " and crawl.active = 1  and ifnull(x.tracker,0) =0"
                            " and DFPM_javascript.iscaptiveportal = 1"
                            " and x.crawl_id= " + hotspot_params["crawl_id"])
            elif iscativeportal == 0:
                    curDest.execute("select distinct x.id, x.url,x.method,x.symbol,x.host,x.level,x.category,x.function_name,x.script_url,x.script_line,x.script_col,ifnull(crawl.website,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner "
                            " from DFPM_javascript x"
                            " inner join crawl on crawl.crawl_id = x.crawl_id"
                            " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                            " where x.active = 1 "
                            " and crawl.active = 1  and ifnull(x.tracker,0) =0"
                            " and DFPM_javascript.iscaptiveportal = 0"
                            " and x.crawl_id= " + hotspot_params["crawl_id"])
            elif iscativeportal == -1:
                    curDest.execute("select distinct x.id, x.url,x.method,x.symbol,x.host,x.level,x.category,x.function_name,x.script_url,x.script_line,x.script_col,ifnull(crawl.website,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner "
                            " from DFPM_javascript x"
                            " inner join crawl on crawl.crawl_id = x.crawl_id"
                            " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                            " where x.active = 1 "
                            " and crawl.active = 1  and ifnull(x.tracker,0) =0"
                            " and x.crawl_id= " + hotspot_params["crawl_id"])
            
        else:
            curDest.execute("select  distinct x.id, x.url,x.method,x.symbol,x.host,x.level,x.category,x.function_name,x.script_url,x.script_line,x.script_col,ifnull(x.url,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = x.basedomain) top_url_owner "
                            " from DFPM_javascript x"
                            " inner join crawl on crawl.crawl_id = x.crawl_id"
                            " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                            " where x.active = 1 and crawl.active = 1 and ifnull(x.tracker,0) =0 "
                            " and x.crawl_id= " + hotspot_params["crawl_id"])   

        rows = curDest.fetchall()
        psl_file = fetch()
        psl = PublicSuffixList(psl_file)
        easylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easylist.txt'))
        privacylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easyprivacy.txt'))
        fanboy = BlockListParser(os.path.join(os.path.dirname(__file__),'fanboy-annoyance.txt'))
        index = 0

        for row in rows:
            try:
                index = index + 1
                row = list(row)
                top_url = row[1]
                url = row[8]


                if row[11] != '': 
                    top_url = 'http://' + row[11] #compare everything to the main website
                
                else:
                    top_url = 'http://unknown.com' #dummy domain since all are considered thirdparty
                
                if row[13] != '': 
                    topurl_owner =  row[13] #compare everything to the main website
                else:
                    topurl_owner = 'unknown top url owner' #dummy domain since all are considered thirdparty

                
                url =  row[8]
                
                if row[12] != '':
                    url_owner =  row[12]
                else:
                    url_owner =  "unknown url owner"


                content_type = 'unknown'
##                if 'about:blank' in top_url: #todo fix does not work
##                     top_url == hotspot_params["LandingPageUrl"]
##
##                if url == ':1':
##                    url = top_url
##                    content_type = 'text/html'
## 
                    
                    
                options = get_option_dict(url, top_url,url_owner,topurl_owner,
                       is_js(url, content_type),
                       is_img(url, content_type),
                       psl)

                if options["third-party"]:
                    thirdparty = 1
                else:
                    thirdparty = 0
                    

                if easylist.should_block(url, options):
                   tracker =1
                   blocked_by ="EasyList"
                elif privacylist.should_block(url,options):
                   tracker =1
                   blocked_by ="EasyPrivacy"
                elif fanboy.should_block(url,options):
                   tracker =1
                   blocked_by ="FanBoy"
                else:    
                   tracker =0
                   blocked_by = ""
                #print (str(row[0]) + '--' + url +   '--' + str(tracker)  ) 
                curDest.execute(" update DFPM_javascript  set thirdparty =" + str(thirdparty) + ", tracker = " + str(tracker) + ", blocked_by='" + blocked_by + "' where id = " +  str(row[0]) )
                cnnDestination.commit()

            except:
                    print ("error")
                    print (top_url)
                    print(url)
                    continue
             

            
    except:
        print ("DFPM thirdparty classification error")



#------------------------------
# update_cookies_tracker_flag
#-----------------------------
def update_cookies_tracker_flag(iscativeportal):

    #try:
        if params["Thirdparty"] == 'website':
                                    
            if iscativeportal == 1:
    
                    curDest.execute(" select distinct x.id,x.crawl_id,x.baseDomain, ifnull(crawl.welcome_page_domain,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.welcome_page_domain) top_url_owner"
                        " from http_profile_cookies  x "
                        " inner join crawl on crawl.crawl_id = x.crawl_id"
                        " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                        " where crawl.active = 1  and x.iscaptiveportal = 1 and and ifnull(x.tracker,0) =0"
                        " and x.crawl_id= " + hotspot_params["crawl_id"])    
            elif iscativeportal == 1:

                    curDest.execute(" select distinct x.id,x.crawl_id,x.baseDomain, ifnull(crawl.website,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                        " from http_profile_cookies  x "
                        " inner join crawl on crawl.crawl_id = x.crawl_id"
                        " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                        " where crawl.active = 1  and x.iscaptiveportal = 0 and ifnull(x.tracker,0) =0"
                        " and x.crawl_id= " + hotspot_params["crawl_id"])    
            elif iscativeportal == -1:

                    curDest.execute(" select distinct x.id,x.crawl_id,x.baseDomain, ifnull(crawl.website,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                        " from http_profile_cookies  x "
                        " inner join crawl on crawl.crawl_id = x.crawl_id"
                        " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                        " where crawl.active = 1  "
                        " and ifnull(x.tracker,0) = 0"             
                        " and x.crawl_id= " + hotspot_params["crawl_id"])    

        else:
              curDest.execute(" select distinct x.id,x.crawl_id,x.baseDomain, ifnull(crawl.welcome_page_domain,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.welcome_page_domain) top_url_owner"
                        " from http_profile_cookies  x "
                        " inner join crawl on crawl.crawl_id = x.crawl_id"
                        " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                        " where crawl.active = 1 "
                        " and x.crawl_id= " + hotspot_params["crawl_id"])   
        
        rows = curDest.fetchall()
        psl_file = fetch()
        psl = PublicSuffixList(psl_file)
        easylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easylist.txt'))
        privacylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easyprivacy.txt'))
        fanboy = BlockListParser(os.path.join(os.path.dirname(__file__),'fanboy-annoyance.txt'))
        index = 0

        for row in rows:
            #try:
                index = index + 1
                row = list(row)
                if row[3] != '': 
                    top_url = 'http://' + row[3] #compare everything to the main website
                
                else:
                    top_url = 'http://unknown.com' #dummy domain since all are considered thirdparty
                
                if row[5] != '': 
                    topurl_owner =  row[5] #compare everything to the main website
                else:
                    topurl_owner = 'unknown top url owner' #dummy domain since all are considered thirdparty

                
                url = 'https://' + row[2]
                
                if row[4] != '':
                    url_owner =  row[4]
                else:
                    url_owner =  "unknown url owner"
                    
                
                
                #unknown content type for cookie
                content_type = 'uknown'
                    
                options = get_option_dict(url, top_url,url_owner,topurl_owner,
                       is_js(url, content_type),
                       is_img(url, content_type),
                       psl)
                if options["third-party"]:
                    thirdparty = 1
                else:
                    thirdparty = 0
                    

                if easylist.should_block(url, options):
                   tracker =1
                   blocked_by ="EasyList"
                elif privacylist.should_block(url,options):
                   tracker =1
                   blocked_by ="EasyPrivacy"
                elif fanboy.should_block(url,options):
                   tracker =1
                   blocked_by ="FanBoy"
                else:    
                   tracker =0
                   blocked_by = ""
                
                #print (str(row[0]) + '--' + url +   '--' + str(tracker)  ) 

                curDest.execute(" update http_profile_cookies  set thirdparty =" + str(thirdparty) + ", tracker = " + str(tracker) + ", blocked_by='" + blocked_by + "' where id = " +  str(row[0]) + ' and crawl_id = ' +  str(row[1]) )
                cnnDestination.commit()
                

            
##    except:
##        print ("cookies error")


#------------------------------
# update_cookies_tracker_flag
#-----------------------------
def update_localstorages_Thirdparty():

    #try:
        if params["Thirdparty"] == 'website':
            
            curDest.execute(" select distinct x.id,x.crawl_id,x.baseDomain, ifnull(crawl.website,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                        " from http_localstorages  x "
                        " inner join crawl on crawl.crawl_id = x.crawl_id"
                        " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                        " where crawl.active = 1 and ifnull(x.tracker,0) =0 "
                        " and x.crawl_id= " + hotspot_params["crawl_id"])    
        else:
              curDest.execute(" select distinct x.id,x.crawl_id,x.baseDomain, ifnull(crawl.welcome_page_domain,'') ,ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.welcome_page_domain) top_url_owner"
                        " from http_localstorages  x "
                        " inner join crawl on crawl.crawl_id = x.crawl_id"
                        " LEFT JOIN List_Domains ON List_Domains.mainHost = x.baseDomain"
                        " where crawl.active = 1 and ifnull(x.tracker,0) =0"
                        " and x.crawl_id= " + hotspot_params["crawl_id"])   
        
        rows = curDest.fetchall()
        psl_file = fetch()
        psl = PublicSuffixList(psl_file)
        easylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easylist.txt'))
        privacylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easyprivacy.txt'))
        fanboy = BlockListParser(os.path.join(os.path.dirname(__file__),'fanboy-annoyance.txt'))
        index = 0

        for row in rows:
            #try:
                #print(row)
                index = index + 1
                row = list(row)
                if row[3] != '': 
                    top_url = 'http://' + row[3] #compare everything to the main website
                
                else:
                    top_url = 'http://unknown.com' #dummy domain since all are considered thirdparty
                
                if row[5] != '': 
                    topurl_owner =  row[5] #compare everything to the main website
                else:
                    topurl_owner = 'unknown top url owner' #dummy domain since all are considered thirdparty

                
                url = 'http://' + row[2]
                
                if row[4] != '':
                    url_owner =  row[4]
                else:
                    url_owner =  "unknown url owner"
                    
                
                
                #unknown content type for cookie
                content_type = 'uknown'
                    
                options = get_option_dict(url, top_url,url_owner,topurl_owner,
                       is_js(url, content_type),
                       is_img(url, content_type),
                       psl)
                if options["third-party"]:
                    thirdparty = 1
                else:
                    thirdparty = 0
                    

                if easylist.should_block(url, options):
                   tracker =1
                   blocked_by ="EasyList"
                elif privacylist.should_block(url,options):
                   tracker =1
                   blocked_by ="EasyPrivacy"
                elif fanboy.should_block(url,options):
                   tracker =1
                   blocked_by ="FanBoy"
                else:    
                   tracker =0
                   blocked_by = ""
                

                curDest.execute(" update http_localstorages  set thirdparty =" + str(thirdparty) + ", tracker = " + str(tracker) + ", blocked_by='" + blocked_by + "' where id = " +  str(row[0]) + ' and crawl_id = ' +  str(row[1]) )
                cnnDestination.commit()
                


        curDest.execute("delete from  http_localstorages"
            " where basedomain = 'newtab'")
        curDest.execute("delete from  http_localstorages"
            " where basedomain like 'javascript:?'")
        
        curDest.execute("delete from  http_localstorages"
            " where basedomain like 'about'")

#----------------------
#parse_http_request_querystring
#----------------------
def parse_http_request_querystring ():
##    try:
            
            curDest.execute("select distinct request_full_uri"
                        "    from http_requests "
                        " INNER JOIN crawl ON http_requests.crawl_id = crawl.crawl_id     "
                        " where ifnull(request_full_uri,'')!=''"
                        " and  crawl.active = 1"
                        " and ifnull(request_full_uri,'') like '%?%'"
                        " and ifnull(request_full_uri,'') like '%=%'"
                        " and querystringparsed is null" 
                        " and http_requests.crawl_id= " + hotspot_params["crawl_id"])
                                
 
            rows = curDest.fetchall()

            for row in rows:
                url = row[0]
                parsedurl = urllib.parse.urlparse(url)
                parsedurl = urllib.parse.parse_qsl (parsedurl.query)
                for key,value in parsedurl:
                    curDest.execute("insert into http_requests_querystring (crawl_id,frame_number,url,key,value) "
                                    " select crawl_id,frame_number,request_full_uri, ?,?"
                                    "  from http_requests"
                                    " where request_full_uri =?", (key,value,url,))
                                    

                curDest.execute("update     http_requests set querystringparsed = 1 where request_full_uri =?", (url,))


            curDest.execute("insert into  leak_category(key,tag,desc)"
                    "   select distinct 'Longitude',value, 'Location' from http_requests_querystring"
                    "   where value like '-73.%'"
                    "   and not exists (select * from leak_category where leak_category.tag = http_requests_querystring.value)")


            curDest.execute("insert into  leak_category(key,tag,desc)"
                    "   select distinct 'Latitude',value, 'Location' from http_requests_querystring"
                    "   where value like '45.%'"
                    "   and not exists (select * from leak_category where leak_category.tag = http_requests_querystring.value)")

            curDest.execute("select distinct referer"
                    "    from http_requests "
                    " INNER JOIN crawl ON http_requests.crawl_id = crawl.crawl_id     "
                    " where ifnull(referer,'')!=''"
                    " and  crawl.active = 1"
                    " and ifnull(referer,'') like '%?%'"
                    " and ifnull(referer,'') like '%=%'"
                    " and referrerquerystringparsed is null"
                    " and referer is not null"   
                    " and http_requests.crawl_id= " + hotspot_params["crawl_id"])
                            
 
            rows = curDest.fetchall()

            for row in rows:
                url = row[0]
                parsedurl = urllib.parse.urlparse(url)
                parsedurl = urllib.parse.parse_qsl (parsedurl.query)
                for key,value in parsedurl:
                    curDest.execute("insert into http_referrer_querystring (crawl_id,frame_number,url,key,value) "
                                    " select crawl_id,frame_number,referer, ?,?"
                                    "  from http_requests"
                                    " where referer=?", (key,value,url,))
                                    
 
                curDest.execute("update     http_requests set referrerquerystringparsed= 1 where referer =?", (url,))

                cnnDestination.commit()


            curDest.execute("select distinct location"
                        "    from http_responses "
                        " INNER JOIN crawl ON http_responses.crawl_id = crawl.crawl_id     "
                        " where ifnull(location,'')!=''"
                        " and  crawl.active = 1"
                        " and ifnull(location,'') like '%?%'"    
                        " and ifnull(location,'') like '%=%'"
                       " and querystringparsed is null  "    
                        " and http_responses.crawl_id= " + hotspot_params["crawl_id"])
                                
 
            rows = curDest.fetchall()

            for row in rows:
                url = row[0]
                
                parsedurl = urllib.parse.urlparse(url)
                parsedurl = urllib.parse.parse_qsl (parsedurl.query)
                for key,value in parsedurl:
                    curDest.execute("insert into http_responses_querystring (crawl_id,frame_number,url,key,value) "
                                    " select crawl_id,frame_number,location, ?,?"
                                    "  from http_responses"
                                    " where location =?", (key,value,url,))

                curDest.execute("update http_responses set querystringparsed = 1 where location =?", (url,))
            cnnDestination.commit()



            curDest.execute("delete from http_responses_querystring"
                        " where rowid not in (select min(rowid)"
                        " from http_responses_querystring"
                        " group by crawl_id,frame_number,url,key,value)")


            curDest.execute("delete from http_requests_querystring "
                        "  where rowid not in (select min(rowid)" 
                        "  from http_requests_querystring" 
                        " group by crawl_id,frame_number,url,key,value)")


##    except Exception as e:
##        print ("http_requests_querystring")
##        print(e)




            
#----------------------
#Read Http request
#----------------------
def update_http_request_tracker_flag (iscaptiveportal):
##    try:
            
            psl_file = fetch()
            print (os.path.join(os.path.dirname(__file__),'easyprivacy.txt'))
            psl = PublicSuffixList(psl_file)
            easylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easylist.txt'))
            privacylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easyprivacy.txt'))
            fanboy = BlockListParser(os.path.join(os.path.dirname(__file__),'fanboy-annoyance.txt'))
            

            if params["Thirdparty"] == 'website':
                    if iscaptiveportal == 1:#welcome page
                        curDest.execute("select distinct http_requests.crawl_id,http_requests.frame_number,content_type,request_full_uri,top_url,referer,ifnull(crawl.welcome_page_domain,''),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.welcome_page_domain) top_url_owner"
                                " from http_requests "
                                " INNER JOIN crawl ON http_requests.crawl_id = crawl.crawl_id     "
                                " left join http_responses on  http_responses.request_in = http_requests.frame_number "
                                " and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_requests.baseDomain"
                                " where ifnull(request_full_uri,'')!=''"
                                " and http_requests.iscaptiveportal = 1"    
                                " and  crawl.active = 1 and ifnull(http_requests.tracker,0) =0 "
                                " and http_requests.crawl_id= " + hotspot_params["crawl_id"])
                    elif iscaptiveportal == 0: # website
                         curDest.execute("select distinct http_requests.crawl_id,http_requests.frame_number,content_type,request_full_uri,top_url,referer,ifnull(crawl.website,''),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                                " from http_requests "
                                " INNER JOIN crawl ON http_requests.crawl_id = crawl.crawl_id     "
                                " left join http_responses on  http_responses.request_in = http_requests.frame_number "
                                " and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_requests.baseDomain"
                                " where ifnull(request_full_uri,'')!=''"
                                " and http_requests.iscaptiveportal = 0"    
                                " and  crawl.active = 1 and ifnull(http_requests.tracker,0) =0"
                                " and http_requests.crawl_id= " + hotspot_params["crawl_id"])
                    elif iscaptiveportal == -1: #both depends on website
                        curDest.execute("select distinct http_requests.crawl_id,http_requests.frame_number,content_type,orgrequest_full_uri,top_url,referer,ifnull(crawl.website,''),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                                " from http_requests "
                                " INNER JOIN crawl ON http_requests.crawl_id = crawl.crawl_id     "
                                " left join http_responses on  http_responses.request_in = http_requests.frame_number "
                                " and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_requests.baseDomain"
                                " where ifnull(request_full_uri,'')!=''"
                                " and  crawl.active = 1 and ifnull(http_requests.tracker,0) =0  and http_requests.active = 1"
                                " and http_requests.crawl_id= " + hotspot_params["crawl_id"])
            else:
                    curDest.execute("select distinct http_requests.crawl_id,http_requests.frame_number,content_type,request_full_uri,top_url,referer,ifnull(crawl.top_url,ifnull(referer,'')),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner" 
                                " from http_requests "
                                " left join http_responses on  http_responses.request_in = http_requests.frame_number "
                                " and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_requests.baseDomain"
                                " where top_url is not null "
                                " and ifnull(request_full_uri,'')!='' and ifnull(http_requests.tracker,0) =0"
                                " and http_requests.crawl_id= " + hotspot_params["crawl_id"])

            rows = curDest.fetchall()

            for row in rows:

#                print(row)
                t_crawl_id = row[0]
                url = row[3]
                content_type_derived =0
                content_type = row[2]
                if content_type == None:
                        content_type = 'unknown'
                        content_type_derived =1
                frame_number = row[1]

                

              
                if row[6] != '': 
                    top_url = 'http://' + row[6] #compare everything to the main website
                
                else:
                    top_url = 'http://unknown.com' #dummy domain since all are considered thirdparty
                    
                if row[7] != '':
                    url_owner =  row[7]
                else:
                    url_owner =  "unknown url owner"
                 

                if row[8] != '': 
                    topurl_owner =  row[8] #compare everything to the main website
                else:
                    topurl_owner = 'unknown top url owner' #dummy domain since all are considered thirdparty


                    
                options = get_option_dict(url, top_url,url_owner,topurl_owner,
                       is_js(url, content_type),
                       is_img(url, content_type),
                       psl)

                if options["third-party"]:
                    thirdparty = 1
                else:
                    thirdparty = 0


                

                if easylist.should_block(url, options):
                   tracker =1
                   blocked_by ="EasyList"
                elif privacylist.should_block(url,options):
                   tracker =1
                   blocked_by ="EasyPrivacy"
                elif fanboy.should_block(url,options):
                   tracker =1
                   blocked_by ="FanBoy"
                else:    
                   tracker =0
                   blocked_by = ""

                print (url)
                print (tracker)
                if tracker == 1:
                        curDest.execute("update http_requests set tracker=?, blocked_by=?, content_type_derived = ? , thirdparty = ? where crawl_id = ? and frame_number = ?", (tracker,blocked_by,content_type_derived,thirdparty,t_crawl_id,frame_number))
                        cnnDestination.commit()
                        
                curDest.execute("update http_requests set tracker= 1 where  basedomain = 'crashlytics.com' or host = 'graph.facebook.com'")

                
              

                curDest.execute("update http_responses set tracker= 1 where  basedomain = 'crashlytics.com' or host = 'graph.facebook.com'")
          
##    except Exception as e:
##        print ('step: update third party flag')
##        print(e)
##        #print ("file does not exists")

    #return true


#----------------------
#update_http_responses_tracker_flag
#----------------------
def update_http_responses_tracker_flag (iscaptiveportal):
##    try:
            
            psl_file = fetch()
            psl = PublicSuffixList(psl_file)
            easylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easylist.txt'))
            privacylist = BlockListParser(os.path.join(os.path.dirname(__file__),'easyprivacy.txt'))
            fanboy = BlockListParser(os.path.join(os.path.dirname(__file__),'fanboy-annoyance.txt'))
            
            #todo check if we can pass top link instead of referer

            if params["Thirdparty"] == 'website':

                  if iscaptiveportal == 1:                
                        curDest.execute("select distinct http_responses.crawl_id,http_responses.frame_number,content_type,http_responses.location,request_full_uri,referer,ifnull(crawl.welcome_page_domain,''),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.welcome_page_domain) top_url_owner"
                                " from http_responses "
                                " inner JOIN crawl ON http_responses.crawl_id = crawl.crawl_id     "
                                " inner join http_requests on  http_responses.request_in = http_requests.frame_number  and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_responses.baseDomain"
                                " where ifnull(http_responses.location,'')!=''"
                                " and http_responses.baseDomain is not null"    
                                " and ifnull(http_responses.location,'') not like '/%'"    
                                " and ifnull(http_responses.location,'') not like '../%'"    
                                " and  crawl.active = 1  "
                                " and http_requests.iscaptiveportal = 1  and ifnull(http_responses.tracker,0) =0"
                                " and http_responses.crawl_id= " + hotspot_params["crawl_id"])
                  elif iscaptiveportal == 0: #depends website
                        curDest.execute("select distinct http_responses.crawl_id,http_responses.frame_number,content_type,http_responses.location,request_full_uri,referer,ifnull(crawl.website,''),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                                " from http_responses "
                                " inner JOIN crawl ON http_responses.crawl_id = crawl.crawl_id     "
                                " inner join http_requests on  http_responses.request_in = http_requests.frame_number  and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_responses.baseDomain"
                                " where ifnull(http_responses.location,'')!=''"
                                " and http_responses.baseDomain is not null"    
                                " and ifnull(http_responses.location,'') not like '/%'"    
                                " and ifnull(http_responses.location,'') not like '../%'"    
                                " and  crawl.active = 1 "
                                " and http_requests.iscaptiveportal = 0 and ifnull(http_responses.tracker,0) =0"
                                " and http_responses.crawl_id= " + hotspot_params["crawl_id"])
                  elif iscaptiveportal == -1: #both depends on website
                        curDest.execute("select distinct http_responses.crawl_id,http_responses.frame_number,content_type,http_responses.location,request_full_uri,referer,ifnull(crawl.website,''),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner"
                                " from http_responses "
                                " inner JOIN crawl ON http_responses.crawl_id = crawl.crawl_id     "
                                " inner join http_requests on  http_responses.request_in = http_requests.frame_number  and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_responses.baseDomain"
                                " where ifnull(http_responses.location,'')!=''"
                                " and http_responses.baseDomain is not null"    
                                " and ifnull(http_responses.location,'') not like '/%'"    
                                " and ifnull(http_responses.location,'') not like '../%'"    
                                " and  crawl.active = 1 and ifnull(http_responses.tracker,0) =0"
                                " and http_responses.crawl_id= " + hotspot_params["crawl_id"])
            else:
                    curDest.execute("select distinct http_responses.crawl_id,http_responses.frame_number,content_type,http_responses.location,request_full_uri,referer,ifnull(crawl.top_url,ifnull(referer,'')),ifnull(List_Domains.parent, ifnull(List_Domains.ownedby,'')) ownedby, (select ifnull(y.parent, ifnull(y.ownedby,'')) from List_Domains y where y.mainHost = crawl.website) top_url_owner" 
                                " from http_responses "
                                " inner JOIN crawl ON http_responses.crawl_id = crawl.crawl_id     "
                                " inner join http_requests on  http_responses.request_in = http_requests.frame_number  and http_responses.crawl_id = http_requests.crawl_id  "
                                " LEFT JOIN List_Domains ON List_Domains.mainHost = http_responses.baseDomain"
                                " where  ifnull(http_responses.location,'')!=''"
                                " and http_responses.baseDomain is not null"
                                " and ifnull(http_responses.location,'') not like '/%'"    
                                " and ifnull(http_responses.location,'') not like '../%'"
                                " and ifnull(http_responses.tracker,0) =0"    
                                " and http_responses.crawl_id= " + hotspot_params["crawl_id"])

            rows = curDest.fetchall()

            for row in rows:
                t_crawl_id = row[0]
                url = row[3]
                content_type_derived =0
                content_type = row[2]
                if content_type == None:
                        content_type = 'unknown'
                        content_type_derived =1
                frame_number = row[1]

             
              
                if row[6] != '': 
                    top_url = 'http://' + row[6] #compare everything to the main website
                
                else:
                    top_url = 'http://unknown.com' #dummy domain since all are considered thirdparty
                    

                if row[7] != '':
                    url_owner =  row[7]
                else:
                    url_owner =  "unknown url owner"
                 

                if row[8] != '': 
                    topurl_owner =  row[8] #compare everything to the main website
                else:
                    topurl_owner = 'unknown top url owner' #dummy domain since all are considered thirdparty


                    
                options = get_option_dict(url, top_url,url_owner,topurl_owner,
                       is_js(url, content_type),
                       is_img(url, content_type),
                       psl)

                if options["third-party"]:
                    thirdparty = 1
                else:
                    thirdparty = 0

                

                if easylist.should_block(url, options):
                   tracker =1
                   blocked_by ="EasyList"
                elif privacylist.should_block(url,options):
                   tracker =1
                   blocked_by ="EasyPrivacy"
                elif fanboy.should_block(url,options):
                   tracker =1
                   blocked_by ="FanBoy"
                else:    
                   tracker =0
                   blocked_by = ""


                curDest.execute("update http_responses set tracker=?, blocked_by=? , thirdparty = ? where crawl_id = ? and frame_number = ?", (tracker,blocked_by,thirdparty,t_crawl_id,frame_number))
                cnnDestination.commit()
                
                
              
          
##    except Exception as e:
##        print ('step: update third party flag')
##        print(e)
##        #print ("file does not exists")

    #return true
    
#----------------------
#Read Http request
#----------------------
def upload_http_request ():
    #try: todo return
 

        csv.field_size_limit(1000000000)
        copyfile(directory_path +"/sslkeylog.log", params["SSLKeyPath"] +"/sslkeylog.log")
        print ("Importing Normal Traffic data ....waiting")

        GenerateCsvFiles(params["PowerShellScript"], directory_path)
        
        f=open(directory_path + '/httprequest.csv','r') # open the csv data file
         
        next(f, None) # skip the header row
        reader = csv.reader(f)#, delimiter='\t', quoting=csv.QUOTE_NONE)
			 
        for row in reader:
            #if row[17] != '':    
                    frame_number = row[0]

                    # search for user mac address  
                    if (row[8]  =='detectportal.firefox.com') or (row[9] =='http://gstatic.com/generate_204') or (row[9] == 'http://www.msftconnecttest.com/connecttest.txt'):
                        mac_id = row[17]
                        user_ip_address = row[1]
                        curDest.execute("update crawl set user_mac_address = '" + mac_id + "', user_ip_address = '" + user_ip_address + "' where crawl_id = " + hotspot_params["crawl_id"] )

                    curDest.execute("select crawl_id,frame_number from http_requests where crawl_id=? and frame_number=?", (hotspot_params["crawl_id"],frame_number))
                    data = curDest.fetchone()

                    

                    if data == None:
                            #decode url
                            row[8] = urllib.parse.unquote(row[8])
                            row[9] = urllib.parse.unquote(row[9])
                            row[15] = urllib.parse.unquote(row[15])
                            row[16] = urllib.parse.unquote(row[16])
                            row[17] = urllib.parse.unquote(row[17])
                            list1 = tldextract.extract(row[9])



                            if list1.suffix != '':
                                domain_name = list1.domain + '.' + list1.suffix
                            else:
                                domain_name = list1.domain
                                
          
                            if list1.subdomain!= '':
                                host = list1.subdomain + '.' + domain_name
                            else:
                                host = domain_name


                            row[10]  = urllib.parse.unquote(row[10])
                            
                            list1 = tldextract.extract(row[10])
                            if list1.suffix != '':
                                referer_domain_name = list1.domain + '.' + list1.suffix
                            else:
                                referer_domain_name = list1.domain
                                
          
                            if list1.subdomain!= '':
                                referer_host = list1.subdomain + '.' + referer_domain_name
                            else:
                                referer_host = referer_domain_name

                            
                            tracker= 0

                            curDest.execute("INSERT INTO http_requests (crawl_id,basedomain,referer_host,referer_basedomain,tracker,frame_number,ip_src,tcp_srcport,ip_dst,tcp_dstport,request_version,user_agent,request_method,host,request_full_uri,referer,cookie,r_header,crawldate,crawltime,text,json_file,mac_id)"
                                    "VALUES (" + hotspot_params["crawl_id"] + ",'" + domain_name + "','" + referer_host + "','" + referer_domain_name + "'," + str(tracker) + ",?, ?, ?,?,?, ?, ?,?,?,?, ?, ?,?,?, ?, ?,?,?)", row)
                    else:
                            row[15] = urllib.parse.unquote(row[15])
                            row[16] = urllib.parse.unquote(row[16])
##                            print (hotspot_params["crawl_id"])
                            curDest.execute("update http_requests set  text = ?, json_file = ?, mac_id =? where crawl_id = ? and frame_number = ?",(row[15],row[16],row[17],hotspot_params["crawl_id"],frame_number))

        f.close()

        #indicate which traffic was part of captive portal
        curDest.execute(" update HTTP_Requests" 
                               " set IsCaptivePortal = 0 where crawl_id=" +hotspot_params["crawl_id"])

        #remove duplicate records if any
        curDest.execute(" delete from http_requests"
                               " where crawl_id=" +hotspot_params["crawl_id"]+ " and rowid not in (select min(rowid)"
                               " from http_requests"
                               " group by frame_number,crawl_id)")
        #todo fix the original bug
        curDest.execute ("delete from http_requests where  typeof(frame_number) != 'integer' ")


        #if a request is re-occur, mark it as inactive
        curDest.execute(" update HTTP_Requests"
                       " set active = 1 where crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute(" update HTTP_Requests"
                       " set active = 0"
                       " where rowid not in (select min(rowid)"
                       " from http_requests"
                       " group by request_full_uri,text,json_file,crawl_id) and crawl_id=" +hotspot_params["crawl_id"])


        curDest.execute(" update http_requests"
                       " set active = 0 "
                       " where request_full_uri not like 'http%'")

        #cleanup host field
        curDest.execute(" update http_requests "
                    " set  host = replace(replace(replace (host,'www.',''),'www4.',''),'www2.','') where crawl_id=" +hotspot_params["crawl_id"])


#----------------------
#upload_websocket
#----------------------
def upload_websocket ():
    #try: todo return
        #if not os.path.isfile(directory_path + '\\websocket.csv'):
##
##        print (directory_path +"\\sslkeylog.log")
##        print (params["SSLKeyPath"] +"\\sslkeylog.log")
        csv.field_size_limit(1000000000)
        copyfile(directory_path +"\\sslkeylog.log", params["SSLKeyPath"] +"\\sslkeylog.log")
        print ("Importing Web Socket data ....waiting")
        
        GenerateCsvFiles(params["PowerShellScript"], directory_path)
        
        f=open(directory_path + '\\websocket.csv','r') # open the csv data file
         
        next(f, None) # skip the header row
        reader = csv.reader(f)#, delimiter='\t', quoting=csv.QUOTE_NONE)
			 
        for row in reader:
            frame_number = row[0]

            # search for user mac address  
            if (row[8]  =='detectportal.firefox.com') or (row[9] =='http://gstatic.com/generate_204') or (row[9] == 'http://www.msftconnecttest.com/connecttest.txt'):
                mac_id = row[15]
                user_ip_address = row[1]
                curDest.execute("update crawl set user_mac_address = '" + mac_id + "', user_ip_address = '" + user_ip_address + "' where crawl_id = " + hotspot_params["crawl_id"] )

            curDest.execute("select crawl_id,frame_number from websockets where crawl_id=? and frame_number=?", (hotspot_params["crawl_id"],frame_number))
            data = curDest.fetchone()



            if data == None:
                    #decode url
                    row[8] = urllib.parse.unquote(row[8])
                    row[9] = urllib.parse.unquote(row[9])
                    row[16] = urllib.parse.unquote(row[16])
                    row[17] = urllib.parse.unquote(row[17])

                    list1 = tldextract.extract(row[9])



                    if list1.suffix != '':
                        domain_name = list1.domain + '.' + list1.suffix
                    else:
                        domain_name = list1.domain
                        
  
                    if list1.subdomain!= '':
                        host = list1.subdomain + '.' + domain_name
                    else:
                        host = domain_name


                    row[10]  = urllib.parse.unquote(row[10])
                    
                    list1 = tldextract.extract(row[10])
                    if list1.suffix != '':
                        referer_domain_name = list1.domain + '.' + list1.suffix
                    else:
                        referer_domain_name = list1.domain
                        
  
                    if list1.subdomain!= '':
                        referer_host = list1.subdomain + '.' + referer_domain_name
                    else:
                        referer_host = referer_domain_name

                    
                    tracker= 0

                    curDest.execute("INSERT INTO websockets (crawl_id,basedomain,referer_host,referer_basedomain,tracker,frame_number,ip_src,tcp_srcport,ip_dst,tcp_dstport,request_version,user_agent,request_method,host,request_full_uri,referer,cookie,r_header,crawldate,crawltime,mac_id,text,json_file)"
                            "VALUES (" + hotspot_params["crawl_id"] + ",'" + domain_name + "','" + referer_host + "','" + referer_domain_name + "'," + str(tracker) + ",?, ?, ?,?,?, ?, ?,?,?,?, ?, ?,?,?, ?, ?,?,?)", row)
            else:
                    curDest.execute("update websockets set  json_file = ? where crawl_id = ? and frame_number = ?",(row[17],hotspot_params["crawl_id"],frame_number))

        f.close()



#----------------------
#upload_http_request_PID
#----------------------
def upload_http_request_PID ():
    #try: todo return
        if  os.path.isfile(directory_path + '\\output.log'):

            f=open(directory_path + '\\output.log','r') # open the csv data file
             
            for line in f.readlines():
                             
                if line[:6] == 'PID-->':
                    row = line.split("|")   

                    url = row[1]
                    package_name = row[2]

                    curDest.execute("select crawl_id,url,package_name from http_requests_pid where url = ? and crawl_id=?", ( url, hotspot_params["crawl_id"]))
                    data = curDest.fetchone()


                    if data == None:
                            curDest.execute("INSERT INTO http_requests_pid (crawl_id,url,package_name) "
                                    "VALUES (" + hotspot_params["crawl_id"] + ",'" + url + "','" + package_name + "')")

            f.close()


    

#----------------------
#find_str
#----------------------
def find_str(s, char):
    index = 0

    if char in s:
        c = char[0]
        for ch in s:
            if ch == c:
                if s[index:index+len(char)] == char:
                    return index

            index += 1

    return -1

#----------------------
#Read Http response
#----------------------

def upload_http_response ():
    try:
        csv.field_size_limit(1000000000)
        f=open(directory_path + '/httpresponse.csv','r') # open the csv data file
        next(f, None) # skip the header row
        reader = csv.reader(f)#, delimiter='\t', quoting=csv.QUOTE_NONE)
			 
        for row in reader:
                frame_number = row[0]
                curDest.execute("select crawl_id,frame_number from http_responses where crawl_id=? and frame_number=?", (hotspot_params["crawl_id"],frame_number))
                data = curDest.fetchone()

                if data == None:
                    row[11] = urllib.parse.unquote(row[11])
                    aString = row[11]

                    if aString.startswith("//"):
                        aString = aString.replace ("//","http://")

                    elif aString.startswith("/"):
                        
                        curDest.execute("select request_full_uri from http_requests where crawl_id=? and frame_number=?", (hotspot_params["crawl_id"],str(row[1])))
                        data1 = curDest.fetchone()
                        if data1 != None:
                            aString = data1[0] + aString
                            row[11] = aString
                            
                    elif not aString.startswith("http"):
                        curDest.execute("select request_full_uri from http_requests where crawl_id=? and frame_number=?", (hotspot_params["crawl_id"],str(row[1])))
                        data1 = curDest.fetchone()
                        if data1 != None:
                            aString = data1[0] + aString
                            row[11] = aString
                            
                    row[16] = urllib.parse.unquote(row[16])
                    row[17] = urllib.parse.unquote(row[17])

                    try:
                        host = ''
                        domain_name = ''
                        if aString.startswith("http"):
                            list1 = tldextract.extract(aString)
                            if list1.suffix != '':
                                domain_name = list1.domain + '.' + list1.suffix
                            else:
                                domain_name = list1.domain
                                
                            if list1.subdomain!= '':
                                host = list1.subdomain + '.' + domain_name
                            else:
                                host = domain_name
                                
                    except:
                        
                        domain_name = ''
                        host =''

                    curDest.execute("INSERT INTO http_responses (crawl_id,host,basedomain,frame_number,request_in,ip_src,tcp_srcport,ip_dst,tcp_dstport,response_code,response_code_desc,response_phrase,content_type,content_length,location,set_cookie,r_header,crawldate,crawltime,text,json_file)"
                            "VALUES (" + hotspot_params["crawl_id"] + ",'" + host + "','" + domain_name + "',?, ?, ?,?,?, ?, ?,?,?, ?, ?,?,?,?, ?,?,?,?)", row)
                else:
                       row[16] = urllib.parse.unquote(row[16])
                       row[17] = urllib.parse.unquote(row[17])
                       curDest.execute("update http_responses set text =?, json_file = ? where crawl_id = ? and frame_number = ?",(row[16],row[17],hotspot_params["crawl_id"],frame_number))
        
        f.close()
    except Exception as e:
        print ('step: import http response')
        print(e)


    curDest.execute(" update HTTP_Responses"
                               " set IsCaptivePortal = 0 where crawl_id=" +hotspot_params["crawl_id"])

    #remove duplicate records if any
  
    curDest.execute(" delete from http_responses"
                               " where crawl_id=" +hotspot_params["crawl_id"] + " and rowid not in (select min(rowid)"
                               " from http_responses"
                               " group by frame_number,crawl_id)")
    #todo fix the original bug
    curDest.execute ("delete from http_responses where  typeof(frame_number) != 'integer' ")

        
    
    #cleannup data

    curDest.execute(" update http_responses "
                    " set  host = replace(replace(replace (host,'www.',''),'www4.',''),'www2.','') where crawl_id=" +hotspot_params["crawl_id"])


#----------------------
#Read Http  cookies
#----------------------

def upload_js_cookies():
   # try:

        if hotspot_params["Browsertype"] == "Firefox":
             file= os.path.join(directory_path,"Browser_Profile","browser-extension-data","Hotspots@1.0",'storage.js')
             if  os.path.isfile(file):
                 index = 0
                 with open(file,"r") as f:
                     for line in f:
                        # try:
                              output = json.loads(line)
                              #print(output)
                              if "set_cookie" in output:
                                  for row in output["set_cookie"]:
                                      cookie  = json.loads(row)
                                      
                                      curDest.execute("select crawl_id, name,basedomain from http_profile_cookies where crawl_id=? and name=? and host=?", (hotspot_params["crawl_id"],cookie["name"],cookie["domain"]))
                                      data = curDest.fetchone()

                                      if cookie["session"]:
                                          expiry = 0
                                      else:
                                          #expiry = cookie["expirationDate"] * 10000000
                                          expiry = cookie["expirationDate"]

                                      domain=  cookie["domain"]
                                      domain = "http://" + domain

                                      list1 = tldextract.extract(domain)
                                      if list1.suffix != '':
                                        domain_name = list1.domain + '.' + list1.suffix
                                      else:
                                        domain_name = list1.domain
         
                                      if data == None:
                                            query = "INSERT INTO http_profile_cookies ( crawl_id,name,value,baseDomain,hostOnly,path,isSecure,ishttponly,expiry,firstpartyonly,host,source,creationTime) VALUES "\
                                                     "(?,?,?,?,?,?,?,?,?,?,?,?,?)"
                                            curDest.execute(query,(hotspot_params["crawl_id"], cookie["name"], cookie["value"], domain_name, cookie["hostOnly"], cookie["path"], cookie["secure"], cookie["httpOnly"], expiry,cookie["firstPartyDomain"],cookie["domain"],'js',cookie["createdate"]))
   
        else:
                uploadchrome_level()
                        # except Exception as e:
                        #     print(e)
                        #     continue

    #except Exception as e:
    #    print ('step: import http  cookies')
    #    print(e)


        curDest.execute(" update http_profile_cookies"
                     " set host = substr(host,2) "
                     "  WHERE host like '.%'" )


#----------------------
#Read Http  cookies
#----------------------

def upload_http_cookies():
#    try:

        if hotspot_params["Browsertype"] == "Firefox":
            curSource.execute("select distinct crawl_id,host,baseDomain,name,value,path,expiry,accessed,CreationTime,isSecure,ishttponly,inbrowserElement,samesite,null,null,null,stage from firefox_profile_cookies order by id desc")
        else:    
            curSource.execute("select distinct crawl_id,host_key,null, name, decrypted_value,path, expires_utc,last_access_utc,creation_utc,is_secure,is_httponly,null,null, is_persistent,priority,firstpartyonly,stage  from chrome_profile_cookies order by id desc")
        rows = curSource.fetchall()

        for row in rows:
                row = list(row)
                row[0] =hotspot_params["crawl_id"]
           
                host_key = row[1]
                if host_key.startswith("."):
                    host_key= host_key[1:]
                if hotspot_params["Browsertype"] != "Firefox":
                    row[2] = host_key

                    if row[6] != 0:
                        row[6] = (row[6] /1000000) -11644473600
                        
                    row[8] = (row[8] /1000000) -11644473600
                else:    
                    #row[6] = row[6] * 10000000
                    #row[6] = row[6] *10
                    row[8] = row[8] /1000000

                name = row[3]
                curDest.execute("select crawl_id, name from http_profile_cookies where crawl_id=? and name=? and host=?", (hotspot_params["crawl_id"],name,host_key))
                data = curDest.fetchone()

                if data == None:
                    if row[16] == "last":
                        row[16] = 0
                    else:
                        row[16] = 1


                    if row[4] != None:    
                            row[4] = urllib.parse.unquote(row[4])
                    else:
                            row[4] = ""

                    domain=  row[1]
                    domain = "http://" + domain
                    
                    list1 = tldextract.extract(domain)
                    
                    if list1.suffix != '':
                        domain_name = list1.domain + '.' + list1.suffix
                    else:
                        domain_name = list1.domain

                    row[2] =    domain_name                
                    
                    query = "INSERT INTO http_profile_cookies ( crawl_id,host,baseDomain,name,value,path,expiry,accessed,CreationTime,isSecure,ishttponly,inbrowserElement,samesite,is_persistent,priority,firstpartyonly,loaded_before_auth) VALUES "\
                             "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                    curDest.execute(query,row)
                else:
                    loaded_before_auth = row[16]
                    if loaded_before_auth == "first":
                         if hotspot_params["Browsertype"] == "Firefox":
                            curDest.execute("update  http_profile_cookies set loaded_before_auth = 1 where crawl_id=? and name=? and host=?", (hotspot_params["crawl_id"],name,host_key))
                         else:
                            curDest.execute("update  http_profile_cookies set loaded_before_auth = 1 where crawl_id=? and name=? and host=?", (hotspot_params["crawl_id"],name,host_key))
                           


         
        curDest.execute(" delete from http_profile_cookies"
                               " where crawl_id=" +hotspot_params["crawl_id"] + " and rowid not in (select min(rowid)"
                               " from http_profile_cookies"
                               " group by name,baseDomain,crawl_id)")


        #alculate the expiry date
        if hotspot_params["Mobile"]== "No":
                curDest.execute("update http_profile_cookies  "
                       "      set millis = Cast ((JulianDay(datetime((expiry),'unixepoch') )- JulianDay(datetime((creationTime),'unixepoch') ) ) * 86400000 As Integer)  "
                       "     where expiry != 0 and crawl_id=" +hotspot_params["crawl_id"])
        else:

                curDest.execute("update http_profile_cookies  "
                               "     set millis = Cast ((JulianDay(datetime((expiry/1000000-11644473600),'unixepoch') )- JulianDay(datetime((creationTime/1000000-11644473600),'unixepoch')) ) * 86400000 As Integer)    "
                               "     where expiry != 0 and crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute(" update http_profile_cookies  "
                   "     set seconds=(millis/1000)%60,"
                   "     minutes=(millis/(1000*60))%60,"
                   "     hours=(millis/(1000*60*60))%24,"
                   "     days = (millis/(1000*60*60*24))%365,"
                   "     years = (millis/(1000*60*60*24*365))%365"
                   "     where expiry != 0 and crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute("update http_profile_cookies  "
                   "      set is_persistent = 1 "
                   "     where expiry != 0 and is_persistent is null and crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute("update http_profile_cookies  "
                           "      set is_persistent = 0 "
                           "     where expiry = 0 and is_persistent is null and crawl_id=" +hotspot_params["crawl_id"])



       
        #cleannup data

        curDest.execute(" update http_profile_cookies "
                    " set  host = replace(replace(replace (host,'www.',''),'www4.',''),'www2.','') where crawl_id=" +hotspot_params["crawl_id"])


        #mark all cookies created in the captive portal phase

        #todo check this
        curDest.execute(" update http_profile_cookies"
                    " set  IsCaptivePortal = 0 where crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute(" update http_profile_cookies"
                    " set  IsCaptivePortal = 1"
                    " where http_profile_cookies.Creationtime < ( select x.LandingPageUrl_Load_datetime "
                    "                                                                     from Crawl x "
                    "                                                                     where x.crawl_id = http_profile_cookies.crawl_id )"
                    " and  crawl_id=" +hotspot_params["crawl_id"])


    
#----------------------
#Read Http  Local Storages
#----------------------

def upload_http_Localstorage():
    #try: #todo return

        curSource.execute("select distinct crawl_id,scope, key,value,stage from js_localstorage order by id desc")
        rows = curSource.fetchall()
        

        for row in rows:
            row = list(row)
            scope = row[1]
            key = row[2]
            curDest.execute("select crawl_id, key,scope from http_localstorages where crawl_id=? and key=? and scope=?", (hotspot_params["crawl_id"],key,scope))
            data = curDest.fetchone()

            if data == None:
                if  row[4] == "first":
                    row[4] = 1
                else:
                    row[4] = 0
                domain = scope    
                domain = "http://" + domain + "/"

                list1 = tldextract.extract(domain)
                if list1.suffix != '':
                    domain_name = list1.domain + '.' + list1.suffix
                else:
                    domain_name = list1.domain

                row.append(domain_name)    
                curDest.execute("INSERT INTO http_localstorages (crawl_id,scope,key,value,loaded_before_auth,basedomain)"
                            "VALUES (?,?, ?, ?,?,?)", (hotspot_params["crawl_id"],row[1],row[2],row[3],row[4],row[5]))
            
            else:
                loaded_before_auth = row[4]
                if loaded_before_auth == "first":
                    curDest.execute("update  http_localstorages set loaded_before_auth = 1 where crawl_id =" +  hotspot_params["crawl_id"] + " and key = '" + key  + "' and scope='" +scope+ "'" )



        curDest.execute(" delete from http_localstorages"
                       " where rowid not in (select min(rowid)"
                       " from http_localstorages"
                       " group by crawl_id,scope,key)")
             

   # except Exception as e:
   #     print ('step: import http  local storage')
   #     print(e)


        #cleannup data

        curDest.execute(" update http_localstorages "
                            " set  scope = replace(replace(replace (scope,'www.',''),'www4.',''),'www2.','') where crawl_id=" +hotspot_params["crawl_id"])


#----------------------
#Read Http  session Storages
#----------------------

def upload_http_sessionstorage():
    try:

        curSource.execute("select distinct crawl_id,scope, key,value from js_sessionstorage order by id desc")
        rows = curSource.fetchall()
        

        for row in rows:
            row = list(row)
            scope = row[1]
            key = row[2]
            curDest.execute("select crawl_id, key,scope from http_sessionstorages where crawl_id=? and key=? and scope=?", (hotspot_params["crawl_id"],key,scope))
            data = curDest.fetchone()

            if data == None:
      

                domain=  scope
                domain = "http://" + domain + "/"
                
                list1 = tldextract.extract(domain)
                if list1.suffix != '':
                    domain_name = list1.domain + '.' + list1.suffix
                else:
                    domain_name = list1.domain
        
                row.append(domain_name)
                

                curDest.execute("INSERT INTO http_sessionstorages (crawl_id,scope,key,value,basedomain)"
                            "VALUES (?,?, ?, ?,?)", (hotspot_params["crawl_id"],row[1],row[2],row[3],row[4]))
            
        curDest.execute(" delete from http_sessionstorages"
                       " where rowid not in (select min(rowid)"
                       " from http_sessionstorages"
                       " group by crawl_id,scope,key)")
             
   
    except Exception as e:
        print ('step: import http  session storage')
        print(e)


#-----------------------------------
#upload_crawl_table 
#-----------------------------------
def upload_crawl_table(directory_path):

    Name = hotspot_params["hotspotName"]
    address = hotspot_params["address"]
    crawl_date= hotspot_params["CrawlDate"]
    LandingPageUrl = hotspot_params["LandingPageUrl"]
    welcome_page = hotspot_params["WelcomePageURL"]

    Browsertype =  hotspot_params["Browsertype"]
    ProtectionMethod = "None"
    if "ProtectionMethod" in hotspot_params:
        ProtectionMethod =  hotspot_params["ProtectionMethod"]
    UsedAccount = ""
    if "UsedAccount" in hotspot_params:
        UsedAccount =  hotspot_params["UsedAccount"]
    if "account_email" in hotspot_params:
        account_email =  hotspot_params["account_email"]
    else:
        account_email = ""
    hotspot_params["account_email"] =    account_email 
    if "geoloc_permission" in hotspot_params:
        geoloc_permission =  hotspot_params["geoloc_permission"]
    else:
        geoloc_permission = 'null'
    if "ISP" in hotspot_params:
        ISP =  hotspot_params["ISP"]
    else:
        ISP = ""

    if "package_name" in hotspot_params:
        package_name =  hotspot_params["package_name"]
    else:
        package_name = ""

    if "category" in hotspot_params:
        category =  hotspot_params["category"]
    else:
        category = ""
        
    if "website" in hotspot_params:
        website =  hotspot_params["website"]
    else:
        website = ""

    if "comments" in hotspot_params:
        comments =  hotspot_params["comments"]
    else:
        comments = ""
    if "Critical_Error" in hotspot_params:
        if hotspot_params["Critical_Error"]:
            Critical_Error = "1"
        else:
            Critical_Error = "0"

    else:
        Critical_Error = 'null'
    
    if 'Upload_Polisis'  in hotspot_params:
        if hotspot_params["Upload_Polisis"]:
            Upload_Polisis = "1"
        else:
            Upload_Polisis = "0"
            
    else:
        Upload_Polisis = "null"

    parsed = urllib.parse.urlparse(LandingPageUrl)
   #todo suzan check gar montreal firefox, something eired herarbeat
    #todo check what is x-origin-uid in traffic header
    landing_page_domain = parsed.hostname
    if landing_page_domain != None:
        domain=  landing_page_domain
        domain = "http://" + domain + "/"
        
        list1 = tldextract.extract(domain)
        if list1.suffix != '':
            domain_name = list1.domain + '.' + list1.suffix
        else:
            domain_name = list1.domain

        landing_page_domain = domain_name
    else:
      landing_page_domain =""


    parsed = urllib.parse.urlparse(welcome_page)
   #todo suzan check gar montreal firefox, something eired herarbeat
    #todo check what is x-origin-uid in traffic header
    welcome_page_domain = parsed.hostname
    if welcome_page_domain != None:
            domain=  welcome_page_domain
            domain = "http://" + domain
            
            list1 = tldextract.extract(domain)
            if list1.suffix != '':
                domain_name = list1.domain + '.' + list1.suffix
            else:
                domain_name = list1.domain
    
            welcome_page_domain = domain_name
    else:
        welcome_page_domain = ""

        


    curSource.execute("select * from crawl where upload_crawl_id is not null and upload_crawl_id != ''")
    data = curSource.fetchone()

    #if hotspot data was not uploaded before

    if data == None:

        
        #upload crawl table
        curDest.execute("INSERT INTO Crawl (Name,address,LandingPageUrl,landing_page_domain,WelcomePageURL,welcome_page_domain,Browsertype,ProtectionMethod,UsedAccount,account_email,geoloc_permission,ISP,package_name,website,comments,crawl_date,Critical_Error,Upload_Polisis,category) "
                    " values('"+Name.replace("'","")+"','"+address + "','" + LandingPageUrl+"','"+landing_page_domain+"','" +welcome_page +"','" + welcome_page_domain  + "','"  +Browsertype + "','"  + ProtectionMethod+ "','" +UsedAccount + "','" + account_email + "','" +geoloc_permission + "','" +ISP+  "','" +package_name+ "','" +website+ "','"  +comments+ "','" +crawl_date+ "'," +Critical_Error + ",'" + Upload_Polisis+ "','" + category+ "' )")
   
        cur = curDest.execute('SELECT last_insert_rowid()')
        hotspot_params["crawl_id"] = str(curDest.fetchone()[0])
        print ("New crawl id was created = " + hotspot_params["crawl_id"])

        curSource.execute("update crawl set upload_crawl_id = " +hotspot_params["crawl_id"] )
       
    else:

        # if the hotspot uploaded before
         
        #retrieve the crawl_id if dataset was uploaded before
        hotspot_params["crawl_id"] = str(data[1])
        #check if the record still exists in the db

        curDest.execute("select * from crawl where  crawl_id =" + hotspot_params["crawl_id"])
        data = curDest.fetchone()
        if data == None:
            #upload crawl table
            curDest.execute("INSERT INTO Crawl (crawl_id,Name,address,LandingPageUrl,landing_page_domain,WelcomePageURL,welcome_page_domain,Browsertype,ProtectionMethod,UsedAccount,account_email,geoloc_permission,ISP,package_name,website,comments,crawl_date,Critical_Error,Upload_Polisis,category) "
                        " values(" +hotspot_params["crawl_id"] + ",'"+Name+"','"+address+"','"+LandingPageUrl+"','"+landing_page_domain+"','" +welcome_page + "','"+ welcome_page_domain + "','"  +Browsertype + "','"  + ProtectionMethod+ "','" +UsedAccount + "','" + account_email + "','" + geoloc_permission + "','" +ISP+ "','" +package_name+ "','"+website+ "','" +comments+ "','" +crawl_date+ "'," +Critical_Error + ",'" + Upload_Polisis+ "','" + category+ "' )")
        
            cur = curDest.execute('SELECT last_insert_rowid()')
            print("****************************************************************************")
            hotspot_params["crawl_id"] = str(curDest.fetchone()[0])
            print ("New crawl id was created = " + hotspot_params["crawl_id"])

            curSource.execute("update crawl set upload_crawl_id = " +hotspot_params["crawl_id"] )


           

            
        
    #upload site_visits
    try:        
        curSource.execute("select visit_id,crawl_id,site_url,hash_url,create_time from site_visits where crawl_id = 1")
    except:
        curSource.execute("select visit_id,crawl_id,site_url,hash_url,null from site_visits where crawl_id = 1")
        
    rows = curSource.fetchall()
    for row in rows:
        curDest.execute("select * from site_visits where crawl_id = ? and visit_id = ? " ,( hotspot_params["crawl_id"],row[0]))
        data = curDest.fetchone()
        if data == None:
            site_url = urllib.parse.unquote(row[2])

            
            curDest.execute("INSERT INTO site_visits (visit_id,crawl_id,site_url,hash_url,create_time) "
                            " values("+str(row[0])+","+hotspot_params["crawl_id"]+",'"+site_url+"','"+row[3]+"','"+str(row[4])+"')")


            if str(row[4]) == '':
                curDest.execute("update site_visits set create_time = (select crawlTime "
                                "                                      from http_requests "
                                "                                      where http_requests.crawl_id =site_visits.crawl_id " 
                                "                                      and site_visits.site_url = request_full_uri)"
                                " where create_time is null ")
            

#------------------------------
# upload_extract_links
#-----------------------------
def upload_extract_links():

    try:
        
        curSource.execute("select visit_id,found_on, location,type,hash_url from links_found ")
        rows = curSource.fetchall()
        for row in rows:
            curDest.execute("INSERT INTO links_found (crawl_id,visit_id,found_on, location,type,hash_url)"
                            "VALUES (?,?, ?, ?,?,?)", (hotspot_params["crawl_id"] , row[0],row[1],row[2],row[3],row[4]))
    except:
        try:
            curSource.execute("select visit_id,found_on, location from links_found ")
            rows = curSource.fetchall()
            
            for row in rows:
                curDest.execute("INSERT INTO links_found (crawl_id,visit_id,found_on, location)"
                                "VALUES (?,?, ?, ?)", (hotspot_params["crawl_id"] , row[0],row[1],row[2]))
        except:
            curSource.execute("select null,found_on, location from links_found ")
            rows = curSource.fetchall()
            for row in rows:
                curDest.execute("INSERT INTO links_found (crawl_id,visit_id,found_on, location)"
                                "VALUES (?,?, ?, ?)", (hotspot_params["crawl_id"] , row[0],row[1],row[2]))
            

    curDest.execute(" delete from links_found"
                   " where rowid not in (select min(rowid)"
                   " from links_found"
                   " group by crawl_id,visit_id,found_on,location)")
         



#------------------------------
# check_PII_leaked
#-----------------------------
def check_PII_leaked():
        curDest.execute(" select distinct tag,desc,key, device_related, partialmatch, id"
                        " from leak_category"
                        " where  active = 1 and executed = 0 order by hash asc,id asc") 
 
        rows = curDest.fetchall()
        for row in rows:
             checkdeviceMatch(row[0], row[2],row[3],row[4])

             curDest.execute(" update leak_category set executed= 1 where id =" + str(row[5]))

             cnnDestination.commit()




            
        curDest.execute("select distinct host"
                        "    from hotspot_leak_info "
                        " where mainhost is null")
                                
 
        rows = curDest.fetchall()

        for row in rows:
                    domain = "http://" + row[0] + "/"
                    
                    list1 = tldextract.extract(domain)
                    
                    if list1.suffix != '':
                        domain_name = list1.domain + '.' + list1.suffix
                    else:
                        domain_name = list1.domain

                    curDest.execute(" update hotspot_leak_info set mainhost= ? where mainhost is null and  host =?", (domain_name,row[0]) )


                    

#------------------------------
# checkdeviceMatch
#-----------------------------
def checkdeviceMatch(field_value, field_name, device_related, partialmatch):
    if field_name != None:                 
       if field_name != '' and field_name != '_':                 

            if partialmatch == 0:

                    curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                    " select  distinct http_referrer_querystring.crawl_id, x.frame_number, 0,'referer',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.referer,x.request_full_uri"
                                    " from http_referrer_querystring "
                                    " inner join  crawl on crawl.crawl_id = http_referrer_querystring.crawl_id "
                                    " inner join http_requests x on  x.crawl_id = http_referrer_querystring.crawl_id and  x.frame_number = http_referrer_querystring.frame_number and  x.orgreferer = http_referrer_querystring.orgurl "                           
                                    "  where replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') ='" + field_value.lower() + "' "
                                    "  and crawl.active = 1 and http_referrer_querystring.active = 1"
                                    " and x.active = 1")#" and  x.crawl_id=" + hotspot_params["crawl_id"] )




                    curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url) "
                                    " select  distinct http_requests_querystring.crawl_id, x.frame_number,0, 'request_full_uri',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.request_full_uri" 
                                    " from http_requests_querystring "
                                    " inner join  crawl on crawl.crawl_id = http_requests_querystring.crawl_id "
                                    " inner join http_requests x on  x.crawl_id = http_requests_querystring.crawl_id and  x.frame_number = http_requests_querystring.frame_number and x.orgrequest_full_uri = http_requests_querystring.orgurl "                           
                                    "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') = '" + field_value.lower() + "' )"
                                    "  and crawl.active = 1 and http_requests_querystring.active = 1"
                                    " and x.active = 1"
                                    )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )

                    cnnDestination.commit()


                    curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url,text) "
                                    " select  distinct x.crawl_id,0,'json_file', x.frame_number,0,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal, x.request_full_uri,x.json_file"
                                    " from http_requests x "
                                    " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                    "  where (replace(replace(replace(lower(json_file),'-',''),':',''),'+','')  = '" + field_value.lower() + "' )"
                                    "  and crawl.active = 1"
                                    " and x.active = 1"
                                    )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )
                        
 

                    cnnDestination.commit()

                    curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                    " select  distinct http_Responses_querystring.crawl_id,  y.frame_number,0,'response_location',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.text,x.location "
                                    " from http_Responses_querystring "
                                    " inner join  crawl on crawl.crawl_id = http_responses_querystring.crawl_id "
                                    " inner join http_responses x on  x.crawl_id = http_responses_querystring.crawl_id and  x.frame_number = http_responses_querystring.frame_number and x.orglocation = http_Responses_querystring.orgurl "                           
                                    " inner join http_requests y on  x.crawl_id = y.crawl_id and  x.request_in = y.frame_number"                           
                                    "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') = '" + field_value.lower() + "' ) "
                                    " and y.active = 1 and crawl.active = 1 and http_Responses_querystring.active = 1"
                                    )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )

                    cnnDestination.commit()


 
                    curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text) "
                                    " select  distinct x.crawl_id,null,0,'profile_cookie', x.isSecure,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal, 'cookie:' || x.name || '=' || x.decodedvalue"
                                    " from http_profile_cookies x"
                                    " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                    "  where (replace(lower(x.decodedvalue),'-','') = '" + field_value.lower() + "' ) "
                                    " and crawl.active = 1"
                                    )#" and  crawl.crawl_id=" + hotspot_params["crawl_id"] )
 


                    cnnDestination.commit()
 
                    curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,text) "
                                    " select  distinct x.crawl_id,null,0, 'localstorage',0,x.scope ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,'localstorage:' ||x.key  || '=' || x.decodedvalue" #todo check secured for local
                                    " from http_localstorages x"
                                    " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                    "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') = '" + field_value.lower() + "' ) "
                                    " and crawl.active = 1"
                                    )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )


                    cnnDestination.commit()



            else:

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                            " select  distinct http_referrer_querystring.crawl_id, x.frame_number,1,'referer', 1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.referer,x.request_full_uri"
                                            " from http_referrer_querystring "
                                            " inner join  crawl on crawl.crawl_id = http_referrer_querystring.crawl_id "
                                            " inner join http_requests x on  x.crawl_id = http_referrer_querystring.crawl_id and  x.frame_number = http_referrer_querystring.frame_number and  x.orgreferer = http_referrer_querystring.orgurl "                           
                                            "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' )"
                                            "  and crawl.active = 1"
                                            " and x.active = 1 and http_referrer_querystring.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )

                            #toc = time()
                            print ("1")
                            #print (toc - tic)
                            cnnDestination.commit()




                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url) "
                                            " select  distinct http_requests_querystring.crawl_id, x.frame_number,1,'request_full_uri', 1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.request_full_uri"
                                            " from http_requests_querystring "
                                            " inner join  crawl on crawl.crawl_id = http_requests_querystring.crawl_id "
                                            " inner join http_requests x on  x.crawl_id = http_requests_querystring.crawl_id and  x.frame_number = http_requests_querystring.frame_number and x.orgrequest_full_uri = http_requests_querystring.orgurl"                           
                                            "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' )"
                                            "  and crawl.active = 1"
                                            " and x.active = 1 and http_requests_querystring.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )

                            #toc = time()
                            print ("2")
                            #print (toc - tic)
                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                            " select  distinct x.crawl_id,x.frame_number,1,'request_full_uri',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.text,x.request_full_uri"
                                            " from http_requests x "                       
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " where (replace(replace(replace(lower(request_full_uri),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            "  and crawl.active = 1"
                                            " and x.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )



                            #toc = time()
                            print ("3")
                            #print (toc - tic)
                            cnnDestination.commit()
                            
                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                            " select  distinct x.crawl_id, 'request_form',1, x.frame_number,1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.text,x.request_full_uri"
                                            " from http_requests x "                       
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " where (replace(replace(replace(lower(text),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            "  and crawl.active = 1"
                                            " and x.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )



                            #toc = time()
                            print ("4")
                            #print (toc - tic)
                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                            " select  distinct x.crawl_id,  x.frame_number,1,'http_requests_json_file',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.json_file,x.request_full_uri"
                                            " from http_requests x "                       
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " where (replace(replace(replace(lower(json_file),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            "  and crawl.active = 1"
                                            " and x.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )


                            #toc = time()
                            print ("5")
                            #print (toc - tic)

                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                            " select  distinct x.crawl_id, x.frame_number,1, 'request_cookie',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.cookie,x.request_full_uri"
                                            " from http_requests x   "                        
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " where (replace(replace(replace(lower(cookie),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            "  and crawl.active = 1"
                                            " and x.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )
                          
                            #toc = time()
                            print ("6")
                            #print (toc - tic)
                            cnnDestination.commit()
                            
                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text,url) "
                                            " select  distinct http_Responses_querystring.crawl_id, y.frame_number,1,'response_location',1,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,x.text,x.location"
                                            " from http_Responses_querystring "
                                            " inner join  crawl on crawl.crawl_id = http_responses_querystring.crawl_id "
                                            " inner join http_responses x on  x.crawl_id = http_responses_querystring.crawl_id and  x.frame_number = http_responses_querystring.frame_number and x.orglocation = http_Responses_querystring.orgurl"                           
                                            " inner join http_requests y on  x.crawl_id = y.crawl_id and  x.request_in = y.frame_number"                           
                                            "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            " and y.active = 1 and http_Responses_querystring.active = 1 and crawl.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )

                            #toc = time()
                            print ("7")
                            #print (toc - tic)

                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url,text) "
                                            " select  distinct x.crawl_id, 1,'response_form', http_requests.frame_number,1,http_requests.host ,'"+field_name + "','" + field_value+"',http_requests.thirdparty,http_requests.tracker,http_requests.iscaptiveportal,http_requests.request_full_uri,x.text"
                                            " from  http_responses x"                          
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " inner join  http_requests on http_requests.crawl_id = x.crawl_id and http_requests.frame_number = x.request_in"
                                            " where (replace(replace(replace(lower(x.text),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            " and http_requests.active = 1 and x.active = 1 and crawl.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )


                            #toc = time()
                            print ("8")
                            #print (toc - tic)
                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url,text) "
                                            " select  distinct x.crawl_id, http_requests.frame_number,1,'response_location',1,http_requests.host ,'"+field_name + "','" + field_value+"',http_requests.thirdparty,http_requests.tracker,http_requests.iscaptiveportal,http_requests.request_full_uri,x.text"
                                            " from  http_responses x"                          
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " inner join  http_requests on http_requests.crawl_id = x.crawl_id and http_requests.frame_number = x.request_in"
                                            " where (replace(replace(replace(lower(x.location),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            " and http_requests.active = 1 and x.active = 1 and crawl.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )


                            #toc = time()
                            print ("9")
                            #print (toc - tic)
                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url,text) "
                                            " select  distinct x.crawl_id,  http_requests.frame_number,1,'response_json',1,http_requests.host ,'"+field_name + "','" + field_value+"',http_requests.thirdparty,http_requests.tracker,http_requests.iscaptiveportal,http_requests.request_full_uri,x.json_file"
                                            " from  http_responses x"                          
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " inner join  http_requests on http_requests.crawl_id = x.crawl_id and http_requests.frame_number = x.request_in"
                                            " where (replace(replace(replace(lower(ifnull(x.json_file,'')),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            " and http_requests.active = 1 and x.active = 1 and crawl.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )

                            cnnDestination.commit()
                            
                            #toc = time()
                            print ("10")
                            #print (toc - tic)

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,url,text) "
                                            " select  distinct x.crawl_id, http_requests.frame_number, 1,'response_cookie',1,http_requests.host ,'"+field_name + "','" + field_value+"',http_requests.thirdparty,http_requests.tracker,http_requests.iscaptiveportal,http_requests.request_full_uri,x.set_cookie"
                                            " from  http_responses x"                          
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            " inner join  http_requests on http_requests.crawl_id = x.crawl_id and http_requests.frame_number = x.request_in"
                                            " where (replace(replace(replace(lower(x.set_cookie),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            " and http_requests.active = 1 and x.active = 1 and crawl.active = 1"
                                            )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )



                            #toc = time()
                            print ("11")
                            #print (toc - tic)
                            cnnDestination.commit()

                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,iscaptiveportal,text) "
                                            " select  distinct x.crawl_id,null,1, 'profile_cookie',x.isSecure,x.host ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,x.iscaptiveportal,'cookie:' || x.name || '=' || x.decodedvalue"
                                            " from http_profile_cookies x"
                                            " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                            "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                            " and crawl.active = 1"
                                            )#" and  crawl.crawl_id=" + hotspot_params["crawl_id"] )



                            #toc = time()
                            print ("12")
                            #print (toc - tic)
                            cnnDestination.commit()


                            #tic = time()
                            curDest.execute("insert into   hotspot_leak_info (crawl_id,frame_number,partialmatch,leak_type,ishttps,host,field_name,field_value,thirdparty,tracker,text) "
                                    " select  distinct x.crawl_id,null,1, 'localstorage',0,x.scope ,'"+field_name + "','" + field_value+"',x.thirdparty,x.tracker,'localstorage:' ||x.key  || '=' || x.decodedvalue" #todo check secured for local
                                    " from http_localstorages x"
                                    " inner join  crawl on crawl.crawl_id = x.crawl_id "
                                    "  where (replace(replace(replace(lower(decodedvalue),'-',''),':',''),'+','') like '%" + field_value.lower() + "%' ) "
                                    " and crawl.active = 1"
                                    )#" and  x.crawl_id=" + hotspot_params["crawl_id"] )


                            #toc = time()
                            print ("13")
                            #print (toc - tic)
                            cnnDestination.commit()

    
            curDest.execute(" update hotspot_leak_info"
                       " set ishttps = 0"
                       " where lower(url)  like 'http:%'")
                            
            cnnDestination.commit()

            curDest.execute(" delete from hotspot_leak_info"
                       " where rowid not in (select min(rowid)"
                       " from hotspot_leak_info"
                       " group by crawl_id,leak_type,frame_number,ishttps,host,field_name,field_value,thirdparty,tracker,text,iscaptiveportal,partialmatch)")
            cnnDestination.commit()


#------------------------------
# get_chrome_cookies
#-----------------------------
def get_chrome_cookies(profile_directory):

    cookie_db = os.path.join(profile_directory, 'Cookies')
    if not os.path.isfile(cookie_db):
        print("cannot find cookies", cookie_db)
    else:
        conn = sqlite3.connect(cookie_db)
        with conn:
            c = conn.cursor()
            c.execute('SELECT host_key, name, value, expires_utc, persistent, secure,httponly,last_access_utc,priority,creation_utc,path,firstpartyonly FROM cookies')

            #c.execute('SELECT host_key, name, value, encrypted_value, has_expires, expires_utc, is_persistent, is_secure,is_httponly,last_access_utc,priority,creation_utc,path,firstpartyonly FROM cookies')
            rows = c.fetchall()
        return rows
            

#------------------------------
# dump_Chrome_profile_cookies
#-----------------------------
def dump_Chrome_profile_cookies(directory_path):
#    try:
 
        # Connect to the Database
##        conn = sqlite3.connect( params["database"])
##        cursor = conn.cursor()

        
        #define the output directory of browser profile
        browser_profile = os.path.join(directory_path, "data","app_webview" )
        if  os.path.isfile(os.path.join(browser_profile, 'Cookies')):
                rows = get_chrome_cookies(browser_profile)

                if rows is not None:
                    for row in rows:
                        row = list(row)

                        # Decrypt the encrypted_value
                        host_key = row[0]
                        name = row[1]
                        value = row[2]
                        encrypted_value = row[3]
                        curDest.execute("select 'x' from http_profile_cookies where crawl_id = ?  and host=? and name=?", (hotspot_params['crawl_id'],host_key,name))
                        data = curDest.fetchone()
                        #todo suzan

                        domain=  row[1]
                        domain = "http://" + host_key
                            
                        list1 = tldextract.extract(domain)
                                           

                        if list1.suffix != '':
                            domain_name = list1.domain + '.' + list1.suffix
                        else:
                            domain_name = list1.domain
                            

                        if list1.subdomain!= '':
                            host = list1.subdomain + '.' + domain_name
                        else:
                            host = domain_name
                        row[0] = host

                        row.append(domain_name)
                        row.append(hotspot_params['crawl_id'])
                        
                        if data == None:

                            query = "INSERT INTO http_profile_cookies (" \
                                     "host, name, value, expiry, is_persistent, "\
                                     "issecure,ishttponly,accessed,priority,creationTime,path,firstpartyonly,basedomain,crawl_id) VALUES "\
                                     "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                            curDest.execute(query, row)
           
##        conn.commit()
##        conn.close()


##    except Exception as e:
##        print ("critical: chrome cookies was not captured ")
##        params["criticalerror"] = True

        #alculate the expiry date
        if hotspot_params["Mobile"]== "No":
                curDest.execute("update http_profile_cookies  "
                       "      set millis = Cast ((JulianDay(datetime((expiry),'unixepoch') )- JulianDay(datetime((creationTime),'unixepoch') ) ) * 86400000 As Integer)  "
                       "     where expiry != 0 and crawl_id=" +hotspot_params["crawl_id"])
        else:

                curDest.execute("update http_profile_cookies  "
                               "     set millis = Cast ((JulianDay(datetime((expiry/1000000-11644473600),'unixepoch') )- JulianDay(datetime((creationTime/1000000-11644473600),'unixepoch')) ) * 86400000 As Integer)    "
                               "     where expiry != 0 and crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute(" update http_profile_cookies  "
                   "     set seconds=(millis/1000)%60,"
                   "     minutes=(millis/(1000*60))%60,"
                   "     hours=(millis/(1000*60*60))%24,"
                   "     days = (millis/(1000*60*60*24))%365,"
                   "     years = (millis/(1000*60*60*24*365))%365"
                   "     where expiry != 0 and crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute("update http_profile_cookies  "
                   "      set is_persistent = 1 "
                   "     where expiry != 0 and is_persistent is null and crawl_id=" +hotspot_params["crawl_id"])

        curDest.execute("update http_profile_cookies  "
                           "      set is_persistent = 0 "
                           "     where expiry = 0 and is_persistent is null and crawl_id=" +hotspot_params["crawl_id"])





#------------------------------
# upload_DFPM
#-----------------------------
def upload_DFPM():

    #try:
        curSource.execute("select crawl_id, url,method,symbol,host,level,category,function_name,script_url,script_line,script_col from DFPM_javascript")
        rows = curSource.fetchall()
        for row in rows:
            
            row = list(row)
            row[0] = hotspot_params["crawl_id"]
            try:
                if row[8] == 'about:blank': #todo check
                    domain_name = row[8]
                elif row[8] == ':1':
                    row[8] = row[1]
                    list1 = tldextract.extract(row[1])

                    domain_name = list1.domain + '.' + list1.suffix
                else:    
                    list1 = tldextract.extract(row[8])

                    domain_name = list1.domain + '.' + list1.suffix

            except:
                domain_name = row[8]

            #print (row)    
                
            curDest.execute("INSERT INTO DFPM_javascript (crawl_id, url,method,symbol,host,level,category,function_name,script_url,script_line,script_col,basedomain)"
                            "VALUES (?,?, ? , ? , ?,?,?,?,?,?,?,'" +  domain_name + "')", row)
         

        curDest.execute(" delete from DFPM_javascript"
                       " where rowid not in (select min(rowid)"
                       " from DFPM_javascript"
                       " group by crawl_id,level,category,url,method,host,script_url,script_line,script_col)")
        
    #except:
    #    print ("DFPM is not captured")

        #cleannup data


        curDest.execute(" update DFPM_javascript "
                            " set  host = replace(replace(replace (host,'www.',''),'www4.',''),'www2.','') where crawl_id=" +hotspot_params["crawl_id"])



#---------------------------
# updatecallingapps
#---------------------------

def updatecallingapps():


            curDest.execute("  update http_requests"
                            " set calling_app = null, active = 1"
                           )#" where http_requests.crawl_id=" +hotspot_params["crawl_id"])
            cnnDestination.commit()


            curDest.execute(" update http_requests"
                       " set active = 0 "
                       " where request_full_uri not like 'http%'")


            curDest.execute(" update HTTP_Requests"
                       " set active = 0"
                       " where rowid not in (select min(rowid)"
                       " from http_requests"
                       " group by request_full_uri,text,json_file,crawl_id)")
            cnnDestination.commit()



            curDest.execute("select distinct x.package_name,x.orgurl,x.crawl_id from http_requests_pid x" )
            rows = curDest.fetchall()
            for row in rows:
                    curDest.execute(" update HTTP_Requests"
                                       " set calling_app = ? "
                                       " where orgrequest_full_uri =?"
                                      "  and crawl_id= ?", (row[0],row[1],row[2],))
                    cnnDestination.commit()



            curDest.execute("select distinct x.package_name,x.isp,x.crawl_id from crawl x where active = 1" )
            rows = curDest.fetchall()
            for row in rows:
                    curDest.execute("  update http_requests"
                                    " set calling_app = ifnull(calling_app,'') || '>>' || ?"
                                    " where (replace(lower(referer),'-','') like  ?"
                                    " or replace(lower(referer),'-','') like  ?"
                                    " or replace(lower(request_full_uri),'-','') like ?"
                                    " or replace(lower(request_full_uri),'-','') like ?"
                                    " or replace(lower(user_agent),'-','') like ?"
                                    " or replace(lower(user_agent),'-','') like ?"
                                    " or replace(lower(r_header),'-','') like  ?"
                                    " or replace(lower(r_header),'-','') like ?"
                                    " ) "
                                    #" and http_requests.calling_app not  like ?"
                                    #" and http_requests.calling_app not  like ?"
                                    " and http_requests.crawl_id = ?", (row[0],'%'+row[0]+'%','%'+row[1]+'%','%'+row[0]+'%','%'+row[1]+'%','%'+row[0]+'%','%'+row[1]+'%','%'+row[0]+'%','%'+row[1]+'%',row[2],))
                    cnnDestination.commit()

                    curDest.execute("  update http_requests"
                            " set active = 0, calling_app =  ifnull(calling_app,'') || '>>' || 'shouldnotbeincluded'"
                            " where http_requests.calling_app not  like ?"
                            " and http_requests.calling_app not  like ?"
                            " and active = 1 and calling_app is not null"
                            " and http_requests.crawl_id = ?", ('%'+row[0]+'%','%'+row[1]+'%',row[2],))#" and http_requests.crawl_id=" +hotspot_params["crawl_id"] )

                    cnnDestination.commit()
                                    

            curDest.execute("  update http_requests"
                                    " set active = 0, calling_app = 'undertermined'"
                                    " where  calling_app is  null and active = 1"
                             )#" and http_requests.crawl_id=" +hotspot_params["crawl_id"] )
            cnnDestination.commit()

            curDest.execute("  update http_requests"
                            " set active = 0, calling_app = 'excludebrowsingtraffic' "
                            " where (referer_host like '%concordia%' or host  like '%concordia%' "
                            " or referer_host like '%live.com%' or host  like '%live.com%' "
                            " or referer_host like '%office365.com%' or host  like '%office365.com%' "
                            " or referer_host like '%hotmail.com%' or host  like '%hotmail.com%' "
                            " or referer_host like '%sslab.com%' or host  like '%sslab.com%'"
                            " or referer_host like '%ssllab%' or host  like '%ssllab%' "
                            " or calling_app like '%com.enhance.gameservice%'"
                            " or r_header like '%_i_processes: com.google.android.gms.persistent%' "
                            " or r_header like '%X-Requested-With: com.kiddoware.kidsafebrowser%' )"
                            " and active = 1")


            
            curDest.execute("  update http_responses"
                             " set active = 0"
                             " where exists (select 'x' from http_Requests "
                                             " where frame_number = request_in "
                                             " and http_Requests.crawl_id = http_responses.crawl_id and http_Requests.active = 0) "
                           " and active = 1")
            curDest.execute("  update http_responses"
                             " set active = 1"
                             " where exists (select 'x' from http_Requests "
                                             " where frame_number = request_in "
                                             " and http_Requests.crawl_id = http_responses.crawl_id and http_Requests.active = 1) "
                           " and active = 0")

            cnnDestination.commit()
#------------------------
# populateListDomains
#------------------------
def populateListDomains():

            curDest.execute(" insert into list_Domains (host,mainhost,imported_from)"
                            " select distinct http_requests.host,http_requests.basedomain,'HTTP'"
                            " from http_requests"
                            " where http_requests.active = 1 and not exists (select 'x' from list_Domains x where x.host = http_requests.host  )"
                            )#" and crawl_id=" +hotspot_params["crawl_id"])
                        
            curDest.execute(" insert into list_Domains (host,mainhost,imported_from)"
                            " select distinct http_responses.host,http_responses.basedomain,'HTTP'"
                            " from http_responses"
                            " where not exists (select 'x' from list_Domains x where x.host = http_responses.host )"
                            "  and http_responses.host is not null and http_responses.active = 1"
                            "  and http_responses.host !=''"
                             )#"  and crawl_id=" +hotspot_params["crawl_id"])

            curDest.execute("  insert into list_Domains (host,mainhost,imported_from)"
                            " SELECT distinct substr(x.host,2),x.baseDomain,'Cookie'"
                            " FROM "
                            " all_cookies x"
                            " where x.baseDomain not in (select list_domains.mainhost from list_domains) "
                            " and x.host like '.%'" #firefox
                             )#" and x.crawl_id=" +hotspot_params["crawl_id"])
            
            curDest.execute("  insert into list_Domains (host,mainhost,imported_from)"
                            " SELECT distinct substr(x.host,2),x.baseDomain,'Cookie'"
                            " FROM "
                            " all_cookies x"
                            " where x.baseDomain not in (select list_domains.mainhost from list_domains)"
                            " and x.host not like '.%'" #chrome
                             )#" and x.crawl_id=" +hotspot_params["crawl_id"])


            curDest.execute("  insert into list_Domains (host,mainhost,imported_from)"
                            " SELECT distinct x.scope,x.baseDomain,'LocalStorage'"
                            " FROM "
                            " http_localstorages x"
                            " where x.scope not in (select list_domains.host from list_domains) "
                            "  and scope !='about:blank' and  scope !='newtab' and  scope !='javascript:''' "
                             )#" and x.crawl_id=" +hotspot_params["crawl_id"])

            curDest.execute(" update list_domains"
                            " set parent = (select x.parent from list_domains x where x.mainhost = list_domains.mainhost and x.parent is not null)"
                            " where list_domains.parent is null")

            curDest.execute(" update list_domains"
                            " set ownedby = (select x.ownedby from list_domains x where x.mainhost = list_domains.mainhost and x.ownedby is not null)"
                            " where list_domains.ownedby is null")

            curDest.execute(" update list_domains"
                            " set source = (select x.source from list_domains x where x.mainhost = list_domains.mainhost and x.source is not null)"
                            " where list_domains.source is null")



            curDest.execute(" update list_domains"
                            " set parent = (select x.parent from list_domains x where x.ownedby = list_domains.ownedby and ifnull(x.parent,'')!='')"
                            " where ifnull(list_domains.parent,'')!=''")


            curDest.execute(" update list_domains "
                            " set second_level_domain = substr(mainhost,1,instr(mainhost,'.')-1) "
                            " where second_level_domain is null" )



            #update domain information from whois database
            updateownedby()
          

#---------------------------
#updatethirdparty_flag
#---------------------------
def updatethirdparty_flag():
            curDest.execute(" update http_profile_cookies "
                            " set thirdparty = 0"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_profile_cookies.baseDomain) "
                            "  =  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_profile_cookies.crawl_id )) "
                            " and thirdparty = 1; ")


            curDest.execute(" update http_profile_cookies" 
                            " set thirdparty = 1"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_profile_cookies.baseDomain) "
                            "  !=  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_profile_cookies.crawl_id )) "
                            " and thirdparty = 0;")


            curDest.execute(" update http_localstorages "
                            " set thirdparty = 0"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_localstorages.baseDomain) "
                            "  =  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_localstorages.crawl_id )) "
                            " and thirdparty = 1; ")


            curDest.execute(" update http_localstorages "
                            " set thirdparty = 1"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_localstorages.baseDomain) "
                            "  !=  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_localstorages.crawl_id )) "
                            " and thirdparty = 0;")




            curDest.execute(" update http_requests" 
                            " set thirdparty = 0"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_requests.baseDomain) "
                            "  =  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_requests.crawl_id ))"
                            " and thirdparty = 1 and active = 1;")

            curDest.execute(" update http_requests "
                            " set thirdparty = 1"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_requests.baseDomain) "
                            "  !=  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "  from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_requests.crawl_id ))"
                            " and thirdparty = 0  and active = 1;")


            curDest.execute(" update http_responses"
                            " set thirdparty = 0"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "               where list_domains.mainHost =  http_responses.baseDomain) "
                            "         =  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_responses.crawl_id )) "
                            "        and  thirdparty = 1 and active = 1;")


            curDest.execute(" update http_responses"
                            " set active = 1"
                            " where exists (select 'x' from http_requests where http_requests.crawl_id = http_responses.crawl_id "
                            "               and  http_requests.frame_number = http_responses.request_in and http_requests.active = 1)"
                            " and  active = 0;")
              

            curDest.execute(" update http_responses"
                            " set active = 0"
                            " where exists (select 'x' from http_requests where http_requests.crawl_id = http_responses.crawl_id "
                            "               and  http_requests.frame_number = http_responses.request_in and http_requests.active = 0)"
                            " and  active = 1;")
              


            curDest.execute(" update http_responses"
                            " set thirdparty = 1"
                            " where (select distinct ifnull(list_domains.parent,list_domains.ownedBy) "
                            "        from list_domains "
                            "        where list_domains.mainHost =  http_responses.baseDomain) "
                            "  !=  (select distinct ifnull(list_domains.parent,list_domains.ownedBy) from list_domains where list_domains.mainHost = (select crawl.website from crawl where crawl.crawl_id =  http_responses.crawl_id ))"
                            "  and thirdparty = 0  and active = 1;")




            curDest.execute("       update http_requests "
                            "       set thirdparty = 0"
                            "       where basedomain in (select ip from list_ips where ifnull(country,'') = '')  and active = 1;")
                             

                           


            curDest.execute("       update http_responses "
                            "       set thirdparty = 0"
                            "       where http_responses.basedomain in (select ip from list_ips where ifnull(country,'') = '')  and active = 1;")
                           



            curDest.execute("      update http_profile_cookies "
                            "      set thirdparty = 0"
                            "      where basedomain in (select ip from list_ips where ifnull(country,'') = '');")
                                                       





##            curDest.execute("      update hotspot_leak_info "
##                            "      set thirdparty = (select http_requests.thirdparty from http_requests where hotspot_leak_info.url = http_requests.request_full_uri and  http_requests.crawl_id = hotspot_leak_info.crawl_id   ) ;")
##
##
##            curDest.execute("      update hotspot_leak_info "
##                            "      set thirdparty = (select http_responses.thirdparty from http_responses where hotspot_leak_info.url = http_responses.location  and  http_requests.crawl_id = hotspot_leak_info.crawl_id) ;")
##
##
##
##
##            curDest.execute("      update hotspot_leak_info "
##                            "      set tracker = (select http_requests.tracker from http_requests where hotspot_leak_info.url = http_requests.request_full_uri  and  http_requests.crawl_id = hotspot_leak_info.crawl_id) ;")
##
##
##            curDest.execute("      update hotspot_leak_info "
##                            "      set tracker = (select http_responses.tracker from http_responses where hotspot_leak_info.url = http_responses.location  and  http_requests.crawl_id = hotspot_leak_info.crawl_id) ;")
##


#---------------------------
#Start Main function calls
#---------------------------

# load general parameters such as database location



action = "7"

main_directory_path = "/root/Desktop/monkeytest/data_analysis/parentalcontrolapps/sample/"

params = load_default_params()

params["action"] = action

#open destination db
cnnDestination = sqlite3.connect(params["database"])
curDest = cnnDestination.cursor()
for directory_path1 in os.listdir(main_directory_path):

    for directory_path in os.listdir(os.path.join(main_directory_path,directory_path1)):
        directory_path = os.path.join(main_directory_path,directory_path1,directory_path)

        # load general hostpot parameters such as database location
        hotspot_params = load_hostspot_default_params(directory_path)

        #check if the hotspot data exists before
        #open source db
        cnnSource = sqlite3.connect(os.path.join(directory_path,"crawl-data.sqlite"))
        curSource = cnnSource.cursor()

        #Upload crawl table data
        upload_crawl_table(directory_path)
        #check required action
        if params["action"] == "1":

            print(" Upload dataset in folder: " + directory_path)
            print (" Crawl ID  = " + hotspot_params["crawl_id"])

                            
            #Upload HTTP Request 
            #-----------------------------------
            upload_http_request()


            # import http response
            #-----------------------------------    
            upload_http_response()
                

            #Upload  HTTP Request Process ID
            #-----------------------------------
            upload_http_request_PID()


            #import cookies from user profile
            #-----------------------------------    
            if hotspot_params["Browsertype"] != "Firefox":
                dump_cookies(directory_path)
                
            if hotspot_params["Mobile"] =='No':
                upload_http_cookies()
                upload_js_cookies()
            else:
                dump_Chrome_profile_cookies(directory_path)



            #import local storage
            #-----------------------------------    
            upload_http_Localstorage()


            #import session storage
            #-----------------------------------    
            upload_http_sessionstorage()


            #import extract link
            #-----------------------------------    
            upload_extract_links()


            #import DFPM
            #-----------------------------------    
            upload_DFPM()
            

            #parse_http_request_querystring
            #-----------------------------------    
            parse_http_request_querystring()




       
        elif params["action"] == "2":
         
            res = input('This function will be run on all datasets, 1=Yes 2=No \n')
            if res == "1":
                    

##                    #parse_http_request_querystring
##                    #-----------------------------------    
##                    parse_http_request_querystring()

                    #remove url decoded characters
                    decodeHttpTraffic()

                    print(" Check the 'base64commoncodes' table to see if new records where added that need to be approved."
                          " The decode64 sometimes generated would decode the text even if it is not base64, "
                          " this is why you have to manually check all new records (approved=0) "
                          " Then if you approve some records, you need to reun this script again"
                          " Note: You can also check the payload to see if they still contains some encoded text. if yes, you can add a record for the code/decodebase64 in 'base64commoncodes'  table."
                          " (in the URL itself or in the payload http_requests.text, http_requests.json_file, http_Responses.text, http_Responses.json_file, http_localstorages.decodedvalue, and http_profile_cookies.decodedvalue)"
                          " This step is still manual, but could be enhanced" )


        elif params["action"] == "3":
                            
            res = input('This function will be run on all datasets, 1=Yes 2=No \n')
            if res == "1":            
##                    #update calling apps field
                    updatecallingapps()
                    print("If you have a custom brwoser app, you need to eliminate the traffic set the http_requests.active = 0 "
                          " \n to eleminate those records generated from the custom browsers (e.g., generated as result of visiting concordia.ca website."
                          " \n then run the below commented sql statment (look in the code) on the database to deactivate the corresponding http_responses."  )

##                    update http_responses
##                             set active = 0
##                             where exists (select 'x' from http_Requests 
##                                              where frame_number = request_in 
##                                              and http_Requests.crawl_id = http_responses.crawl_id and http_Requests.active = 0) 
##                             and active = 1
      
 
        elif params["action"] == "4":

            res = input('This function will be run on all datasets, 1=Yes 2=No \n')
            if res == "1":            
                    #collect all domains into one table
                    populateListDomains()

                    print("You need to check table ListDomain"
                          "\nThe aim is to populate ownedby and parent company based on the methodology discussed in the paper"
                          " This is a manual process for the timebeing")
                  
                       
                    #collect all IPs 
                    populateIps (None)

        elif params["action"] == "5":

                    print("This function will updated the trackers in the selected dataset (crawl_id =" + hotspot_params["crawl_id"] + ")")
                    
                    print ("update_http_request_tracker_flag")
                    update_http_request_tracker_flag(-1)
                    cnnDestination.commit()

                    print ("update_http_responses_tracker_flag")
                    update_http_responses_tracker_flag(-1)


                    print ("update_cookies_tracker_flag")
                    update_cookies_tracker_flag(-1)


                    print ("update_localstorages_Thirdparty")
                    update_localstorages_Thirdparty()   


                    print ("update_DFPM_Thirdparty")
                    update_DFPM_Thirdparty(-1)   

        elif params["action"] == "6":
            res = input('This function will be run on all datasets, 1=Yes 2=No \n')
            if res == "1":            
                    print ("updatethirdparty_flag")
                    updatethirdparty_flag()


        elif params["action"] == "7":
            res = input('This function will be run on all datasets, 1=Yes 2=No \n')
            if res == "1":            
                    print ("make sure your PII are identified in the leak_category table with executed flag=0")
                    print ("make sure the leak_category.desc has word child for child PII, parent for parent PII, "
                           " \n and child/parent for PII shared between child and the parent e.g., home router mac address. This will help you later to filter leaks.")

                    ready = input('Are you ready?, 1=Yes 2=No \n')
                    if ready == "1":            

                            print("Your PII are being hashed")                
                            addhashes()                
                            print ("check_PII_leaked")
                            check_PII_leaked()



        cnnSource.commit()
        cnnSource.close()

        
            

            
        cnnDestination.commit()





cnnDestination.commit()
cnnDestination.close()


