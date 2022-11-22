#!/bin/bash
i=0
dir=$1
mkdir asn
while read line
	do
	    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "$dir")
j=0

while [ $j -ne ${#array[@]} ]
do
IFS=$'\n' read -d '' -r -a data<"$dir/${array[$j]}"
k=0
echo "${array[$j]}"
while [ $k -ne ${#data[@]} ]
do
python3 asn_number.py "${data[$k]}" >> "asn/${array[$j]}"
sleep 0.1
(( k++ ))
 done
(( j++ ))
done


