#!/bin/bash
file=$1
n=$2
	while read line
	do
    		url[ $k ]="$line"        
    		(( k++ ))
	done < "./merged/$file"	
len=${#url[@]}
mkdir "tmp/curl/"$(echo $file | sed 's/\.[^.]*$//')
echo "Working with $file"
for ((l= 0 ; l <=len ; l++)); do
	x-terminal-emulator  -e "timeout 10m ~/go/bin/hakrawler -url "${url[l]}" -depth 4 -urls -insecure | tee "./tmp/curl/"$(echo $file | sed 's/\.[^.]*$//')"/temp_$l.txt""
	echo "Number of website crawled is $l"
	#(( count++ ))
#WAIT UNTIL ALL PREVIOUS 10 PROCESS ARE CLOSED
	#if [ $count -eq 10 ] 
	#then
var=1024
mem_ram=$(awk '/^MemAvailable:/ { print $2; }' /proc/meminfo)

		while [[ $(pgrep hakrawler | wc -l) -gt n ]]; do
		echo "Too many process are running"
	  	sleep 60
		done
		if [[ $((mem_ram / var - 631)) -lt 500 ]]; then
		sleep 90
		fi
		#count=$(pgrep hakrawler | ec -l)
		#while [[ $(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage "%"}' | sed "s/\..*//") -gt 65 ]]; do
		#sleep 60
		done
		echo "Program is working perfectly"
done
exit








echo "Script is running and grabbing URL's From "$file "Any url that doesnot contain "$tld" will be removed at final output"
while IFS= read -r LINE || [[ -n "$LINE" ]]; do
~/go/bin/hakrawler -url $LINE -depth 5 -urls | tee './tmp/log_'$(echo $file) >> "./tmp/temp_"$(echo $file)
cat "./tmp/temp_"$(echo $file) | grep http | sed 's/\[url\]//g' | sort | awk '!seen[$0]++' | sed '/\.jpg/d;/\.mp4/d;/\.docx/d;/\.xls/d;/viber/d;/whatsapp/d;/youtube/d;/facebook/d;/twitter/d;/\.pdf/d' | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> ./tmp/$(echo $file)
done < $(echo $PWD)"/"merged/$file
x-terminal-emulator -e $(echo $PWD)"/"curl.sh $file $tld

