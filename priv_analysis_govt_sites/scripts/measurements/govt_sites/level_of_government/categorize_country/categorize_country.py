import sys
import tldextract
import re
import os

## MAIN ##
def return_country(url):
    arg = url.split("\\")[0]
    ext = tldextract.extract(arg)
    sld = ext.suffix.split(".")[-1]
    country='Unknown'
    d = {}
    with open("country_extension.txt") as f:
        for line in f:
            (key, val) = line.split(',')
            d[val] = key
    #print(sld)
    try:
        native_country=d[sld+'\n']
    except:
        native_country=country
    return native_country

def return_country_search(url1):
    src_dict = ("/root/final_result/websites/successfully_visited_websites/country/") #Specify base directory
    url=url1
    pattern = re.compile (re.escape(url)) #CPatter to search for
    dict_value = dict()
    documents=[]
    for yum_files in os.listdir(src_dict): # obtain list of files in directory
        files = os.path.join(src_dict, yum_files) #join the full path with the names of the files.
        strng = open(files) #We need to open the files
        for lines in strng.readlines(): #We then need to read the files
            try:
                if re.search(pattern, lines): #If we find the pattern we are looking for
                    documents.append(re.sub(r'\..*',"",strng.name.split("/")[6])) #We split using as a delimeter the = sign.
            except:
                print("Error Detected")
    print(url)
    if len(documents) < 1:
        documents.append("Not Found")             
    return(documents[0])
    
def write_file1(url,country):
    outF = open("country/"+country+".txt", "a")
    outF.write(url)
    outF.write("\n")
    outF.close()
    
def write_file(url,country):
    outF = open("country_specified.txt", "a")
    outF.write(url+"|"+country)
    outF.write("\n")
    outF.close()
    
def main():
    with open("api.txt") as file1:
        for line in file1:
            url1=line.split("|")[0].strip()
            url1=url1.strip()
            #print(url1)
            url=line.strip()
            #if not "http" in url1:
                #url1="Garbage URL"
                #url="Garbage URL"
            country=return_country(url1)
            #url=url.split("|")[0]+"|"+url.split("|")[1]+"|"+country+"|"+url.split("|")[3]
            if country == "Unknown":
                country=return_country_search(url1)
            print(url1+"|"+country)
            write_file(url,country)            
            write_file1(url,country)
if __name__ == "__main__":
    main()
