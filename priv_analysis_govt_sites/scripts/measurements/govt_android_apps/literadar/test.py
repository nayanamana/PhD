import literadar
import json
import sys
apk_path=sys.argv[1]
country=sys.argv[2]
apk_name=sys.argv[3]
op=json.loads(literadar.main(apk_path))
def write_file(apk_name,library,type_of_lib,permission):
    outF = open("apk_library_details.txt", "a")
    outF.write(apk_name+"|"+library+"|"+type_of_lib+"|"+permission)
    outF.write("\n")
    outF.close()
def write_file1(apk_name,country,library,type_of_lib):
    outF = open("country_wise/"+country+".txt", "a")
    outF.write(apk_name+"|"+country+"|"+library+"|"+type_of_lib)
    outF.write("\n")
    outF.close()
for x in range(len(op)):
    Library=op[x]["Library"]
    Type=op[x]["Type"]
    if not Library:
        Library="Library_Not Found"
    if not Type:
        Type="Type_Not Found"
    if len(op[x]["Permission"]) > 0:
            for y in range(len(op[x]["Permission"])):
                            write_file(apk_name,Library,Type,op[x]["Permission"][y])
    else:
            write_file(apk_name,Library,Type,"No Permission")      
    
    #write_file1(apk_name,country,Library,Type)    
