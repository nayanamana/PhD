#!/bin/bash
mkdir outside_country
IFS=$'\n' read -d '' -r -a lines < data.txt
j=0
while [ $j -ne ${#lines[@]} ]
do
country_name=$(echo ${lines[j]} | cut -f1 -d ":" | sed 's/ //g')
file=$(echo ${lines[j]} | sed 's/.*://' | sed 's/ //g')
cat "filtered/$file"| grep -i -v $country_name >> "outside_country/$file"
(( j++ ))
done


