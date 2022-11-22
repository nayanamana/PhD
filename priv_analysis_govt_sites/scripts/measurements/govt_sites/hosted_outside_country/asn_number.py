import pyasn
import sys
asndb = pyasn.pyasn('/root/Desktop/project_v5/result_automator/IPASN.DAT')
line = sys.argv[1] 
web_ip= line.split("|")
asn_number = asndb.lookup(web_ip[2])
site=web_ip[0]
visit_id=web_ip[3]
ip=web_ip[2]
print ("ASN="+str(asn_number[0])+"|"+str(site)+"|"+str(visit_id)+"|"+str(ip))

