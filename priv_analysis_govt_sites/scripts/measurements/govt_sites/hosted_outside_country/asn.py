import pyasn
import sys
import csv
with open("asn1.txt") as infile:
    answer = dict(csv.reader(infile,delimiter='|'))
print(answer['AS58469'])

