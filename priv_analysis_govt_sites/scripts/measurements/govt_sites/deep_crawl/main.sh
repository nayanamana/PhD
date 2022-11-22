#!/bin/bash
process_no=$1
mkdir tmp
mkdir output
mkdir tmp/curl
i=0
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls merged)
j=0
while [ $j -ne ${#array[@]} ]
do
echo "Working With ${array[j]}"
x-terminal-emulator -e "./crawl.sh ${array[j]} $process_no"
	while [[ $(pgrep crawl.sh) ]]; do
	:
	done 	
((j++))
done
