from requests_html import HTMLSession
import sys
def check_url(dom):
    #dom = 'lankapage.com'
    url = 'https://' + dom
    is_https = 0
    code = 999
    content_text = ""

    try:
        url = 'https://' + dom
        #Ref: https://stackoverflow.com/questions/56691190/requests-html-httpsconnectionpoolread-timed-out
        session = HTMLSession(verify=False)
        r = session.get(url, timeout=30)
        #if r.status_code == 200:
        if int(str(r.status_code)[:1]) < 4:
            is_https = 1
            code = r.status_code
            content_text = r.html.html
    except Exception as e:
        print(str(e))
        pass

    if is_https == 0:
        try:
            url = 'http://' + dom
            session = HTMLSession(verify=False)
            r = session.get(url, timeout=30)
            is_https = 0
            code = r.status_code
            content_text = r.html.html
        except Exception as e:
            #print(str(e))
            pass
    return {'is_https': is_https, 'code': code, 'content': content_text, 'url': url}

def main():
    z=check_url(sys.argv[1])
    url=z['url']
    #country=sys.argv[2]
    privacy=sys.argv[2]
    is_https=z['is_https']
    print(str(url) + "|" + str(is_https) + "|" + privacy)

if __name__ == "__main__":
    main()    
