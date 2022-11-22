import re
import os
def return_country_search(url1):
    src_dict = ("/root/eclipse-workspace/level_of_government/src/country/") #Specify base directory
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
    #print(url)
    if len(documents) < 1:
        documents.append("Not Visited")   
    else:
        documents[0]="Successfully Visited"           
    return(documents[0])

def tracker_search(url1):
    src_dict = ("/root/eclipse-workspace/level_of_government/src/trackers/") #Specify base directory
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
    #print(url)
    if len(documents) < 1:
        documents.append("Tracker Not found")   
    else:
        documents[0]="Tracker Presence Found"          
    return(documents[0])

def write_file(url,success,tracker):
    outF = open("germany.txt", "a")
    outF.write(url+","+success+","+tracker)
    outF.write("\n")
    outF.close()

def main():
    with open("domains.txt") as file1:
        for line in file1:
            url1=line.split(",")[0].strip()
            url=line.strip()
            tracker=tracker_search(url1)
            success=return_country_search(url1)
            write_file(url,success,tracker)
            print(url+","+success+","+tracker)
if __name__ == "__main__":
    main()