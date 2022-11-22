from bs4 import BeautifulSoup
import requests
import sys
import sqlite3

def main():
    if len(sys.argv) == 1:
        sys.exit(0)
    ID=sys.argv[1]
    url=sys.argv[2]
    country=sys.argv[3]
    if url.startswith("http://"):
        url=url
    else:
        url="http://"+url
        
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.content, 'html.parser')
    
        title = soup.title.string
        print('TITLE:', title)
    
        meta = soup.find_all('meta')
        description_content="Not found"
        keywords_content="Not found"
    
        for tag in meta:
            if 'name' in tag.attrs.keys() and tag.attrs['name'].strip().lower() in ['description']:
                #description=tag.attrs['name'].lower()
                description_content=tag.attrs['content']
                
            if 'name' in tag.attrs.keys() and tag.attrs['name'].strip().lower() in ['keywords']:
                #keywords=tag.attrs['name'].lower()
                keywords_content=tag.attrs['content']
        print(description_content)
        print(keywords_content)
    except:
        title="Could not visit domain"
        description_content="Could not visit domain"
        keywords_content="Could not visit domain"

    save_db(ID,url,country,title,description_content,keywords_content)        
def save_db(*data):
    conn = sqlite3.connect('crawl_db.sqlite')
    c = conn.cursor()
    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='crawl' ''')
    if c.fetchone()[0]!=1 :
        print('Table  doesnot exists.')
        c.execute('''CREATE TABLE crawl (ID integer, URL text, country text, title text, meta_description text, meta_keywords text)''')
    c.execute(''' select count(*) from crawl ''')
    ID=c.fetchone()[0]
    c.execute("INSERT INTO crawl VALUES (?,?,?,?,?,?)",(ID,data[1],data[2],data[3],data[4],data[5]))    
    conn.commit()
    conn.close()
    
    
if __name__ == '__main__':
    main()