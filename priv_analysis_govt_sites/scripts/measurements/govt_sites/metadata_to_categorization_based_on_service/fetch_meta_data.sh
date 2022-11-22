#!/bin/bash
i=0
dir=$1
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "$dir")
j=0

while [ $j -ne ${#array[@]} ]
do
IFS=$'\n' read -d '' -r -a url <"$dir/${array[j]}"
k=0
while [ $k -ne ${#url[@]} ]
do
python3 meta_db.py "1" "${url[k]}" "$(echo ${array[j]} | cut -f1 -d ".")"
(( k++ ))
done
(( j++ ))
done

exit

