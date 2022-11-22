#!/bin/bash
i=0
mkdir output
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "tmp3/")
j=0

while [ $j -ne ${#array[@]} ]
do
mkdir "output/$(echo ${array[j]} | cut -f1 -d ".")"
IFS=$'\n' read -d '' -r -a url <"tmp3/${array[j]}"
k=0
while [ $k -ne ${#url[@]} ]
do
echo "************ Working With ${array[j]} ***************** "
id=$(echo ${url[k]} | awk -F= '{ print $NF }' | cut -f1 -d"&")
echo $id
gplaycli -d $id -f "output/$(echo ${array[j]} | cut -f1 -d".")" |& tee -a output.txt
#x-terminal-emulator -e gplaydl download --packageId $id --path "output/$(echo ${array[j]} | cut -f1 -d".")"
while [[ $(pgrep gplaycli | wc -l) -gt 10 ]]; do
	  	sleep 60
		done

(( k++ ))
done
    (( j++ ))
done
exit


