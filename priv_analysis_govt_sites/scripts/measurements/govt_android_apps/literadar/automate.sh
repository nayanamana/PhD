#!/bin/bash
i=0
dir=$1
mkdir country_wise
while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls "$dir")
j=0

while [ $j -ne ${#array[@]} ]
do
l=0
while read line
	do
    		apk_array[ $l ]="$line"        
    		(( l++ ))
	done < <(ls "$dir/${array[j]}")
k=0
while [ $k -ne ${#apk_array[@]} ]
do
echo "${array[j]}"
python test.py "$dir/${array[j]}/$(echo ${apk_array[k]})" "${array[j]}" "${apk_array[k]}"
(( k++ ))
done
(( j++ ))
done

exit

