#!/bin/bash
#usuage "./grab.sh 
# Use http://www.gksoft.com/govt/en/ as url"
# Provide Country name 
echo Please enter the url
read url
echo Country Name
read country
curl $url --connect-timeout 10 --max-time 5 -s | sed '/Federal Institutions:/,$!d'| sed -n '/Political Parties:/q;p' | tr '[:upper:]' '[:lower:]' | grep -o '<a .*href=.*>'  | sed -e 's/<a /\n<a /g' | sed -e 's/<a .*href=['"'"'"]//' -e 's/["'"'"'].*$//' -e '/^$/ d' | grep // | sed '/https\|http/!d' | sed 's/^http\(\|s\):\/\///g' | grep www | sed 's:/.*::' | sort | awk '!_[$0]++' > $country".txt"
