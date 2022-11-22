#!/bin/bash
i=0
dir=$1
mkdir ipandcountry
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
IFS='|' read -r -a asn_data <<< "${data[$k]}"
country_raw=$(geoiplookup "${asn_data[3]}")
wait
asn_raw=$(echo ${asn_data[0]}| sed 's/.*=//')
asn="AS$asn_raw|"
IFS=',' read -r -a country_data <<< "$country_raw"
country=${country_data[1]}
company_raw=$(rg -F "$asn" asn.txt)
company=$(echo $company_raw| sed 's/.*|//')
echo "${data[$k]}|$country|$company" >> "ipandcountry/${array[$j]}"
sleep 0.1
(( k++ ))
 done
(( j++ ))
done


