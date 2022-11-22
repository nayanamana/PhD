import tldextract
def domain_find(url):
    url = url.replace("http://","").split("\\")[0]
    ext = tldextract.extract(url)
    sld = ext.suffix
    #sld = ext.suffix.split(".")[-1]
    #print(url)
    return sld
    
def write_file(url1,url2,country,text):
    outF = open("possible_trackers_classified.txt", "a")
    outF.write(url1+"|"+url2+"|"+country+"|"+text)
    outF.write("\n")
    outF.close()
def write_file1(url1,url2,country,text):
    outF = open("categorized_country/"+country+".txt", "a")
    outF.write(url1+"|"+url2+"|"+country+"|"+text)
    outF.write("\n")
    outF.close()

def main():
    with open("category.txt") as file1:
        for line in file1:
            url1=line.split("|")[0]
            url2=line.split("|")[1]
            country=line.split("|")[2].strip()
            url_main=domain_find(url1)
            url_host=domain_find(url2)
            if url_main == url_host:
                print("Same Government Tracker")
                write_file(url1,url2,country,"Same Government Tracker")
                write_file1(url1,url2,country,"Same Government Tracker")
            else:
                print("Different Government Tracker")
                write_file(url1,url2,country,"Different Tracker")
                write_file1(url1,url2,country,"Different Tracker")
if __name__ == "__main__":
    main()
