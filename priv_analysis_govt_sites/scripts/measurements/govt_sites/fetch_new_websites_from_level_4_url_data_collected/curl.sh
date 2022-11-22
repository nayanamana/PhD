#!/bin/bash
mkdir result
i=0
	while read line
	do
    		array[ $i ]="$line"        
    		(( i++ ))
	done < <(ls level4_urls)
j=0	
while [ $j -ne ${#array[@]} ]
do	
mkdir "result/$(echo ${array[j]} | sed 's/\.[^.]*$//')"
echo "Working with ${array[j]}" | tee report.log
parallel -k -j 250 curl -L --max-time 10 --connect-timeout 10  "${CURL_ARGS[@]}" -o "result/$(echo ${array[j]} | sed 's/\.[^.]*$//')/"'{#}'.curl_output  '{}' :::: "level4_urls/"${array[j]}
#zip -r "result/$(echo ${array[j]} | sed 's/\.[^.]*$//').zip" "result/$(echo ${array[j]} | sed 's/\.[^.]*$//')"
#mv "result/$(echo ${array[j]} | sed 's/\.[^.]*$//').zip" "/media/root/Seagate Expansion Drive/project/"
#rm -rf "result/$(echo ${array[j]} | sed 's/\.[^.]*$//').zip"
#rm -rf "result/$(echo ${array[j]} | sed 's/\.[^.]*$//')"

(( j++ ))
done
