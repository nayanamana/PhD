#!/bin/bash
echo Please enter the url
read url
echo Top level domain
read tld
echo $url
echo $tld
clear
echo *.gov$tld > "dorks.txt"
echo ************performing ns lookup****************
nslookup -type=ns $url | sed 's/\s\+/\n/g' | grep $tld | sort| sed '$!N; /^\(.*\)\n\1$/!P; D' | grep $tld. | sed 's/^[^.]*.//g'|sed 's/.$//' |sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^/*./'| grep -v zone >> "dorks.txt"
echo ************performing ms lookup****************
nslookup -type=mx $url | sed 's/\s\+/\n/g' | grep $tld | sort| sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^[^.]*.//g'| sort | sed 's/^[^.]*.//g' | sed '$!N; /^\(.*\)\n\1$/!P; D'|sed 's/.$//' | grep $tld | sed 's/^/*./' >> "dorks.txt"
echo ************Google Dorks****************
sed 's/^/site:"/' < dorks.txt > temp.txt
sed 's/.*/&"/' < temp.txt > dork.txt
cat "dork.txt"
echo ************Retriving URLS**************** 
python3 pagodo.py -g dork.txt > result.txt
echo ************Url retrieved****************
sed '/https\|http/!d' < result.txt > result1.txt
sed 's/^http\(\|s\):\/\///g' <result1.txt >result2.txt
sed 's/\/.*//g' < result2.txt | sort > result3.txt
awk '!_[$0]++' < result3.txt | grep $tld > result4.txt
echo ************Urls****************
cat "result4.txt"
cp result4.txt $url".txt"
echo $url >> $url".txt"
#Url grabber starts here
for i in {0..50}
  do 
echo "Running" $i "loop"
file=$url".txt"
while IFS= read line
do
echo "Fetching URL from " $line
curl $line --connect-timeout 10 --max-time 5 -s | grep http >> temp1.txt
done <"$file"
clear
cat temp1.txt | grep -o '<a .*href=.*>'  | sed -e 's/<a /\n<a /g' | sed -e 's/<a .*href=['"'"'"]//' -e 's/["'"'"'].*$//' -e '/^$/ d' | grep $tld | grep // | sed '/https\|http/!d' | sed 's/^http\(\|s\):\/\///g' | grep www | sed 's:/.*::' | sort | awk '!_[$0]++' | grep $tld  > temp.txt
cat $url".txt" >> temp.txt
cat temp.txt | sort | awk '!_[$0]++' > $url".txt"
 done
#mv "result4.txt" $url".txt"
rm -rf dorks.txt dork.txt temp.txt result.txt result1.txt result2.txt result3.txt result4.txt temp1.txt


